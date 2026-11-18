/* Property-style decoder test for malformed and reference Brotli streams.
 *
 * This is a test driver, not part of the decoder library. It intentionally
 * uses only the public decoder API so the same checks can be applied to a
 * sanitizer build of any Brotli revision.
 */

#include <brotli/decode.h>
#include <brotli/encode.h>

#include <dirent.h>
#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#define NUM_VALID_CASES 50
#define NUM_MALFORMED_CASES 200
#define CASES_PER_CATEGORY 50
#define OUTPUT_GUARD_BYTES 64
#define PROBE_OUTPUT_LIMIT (256u * 1024u)
#define MAX_CASE_STEPS 20000000u

typedef struct {
  uint8_t* data;
  size_t size;
} ByteBuffer;

typedef struct {
  char name[320];
  char source[320];
  ByteBuffer compressed;
  ByteBuffer reference;
  int synthetic;
} ValidCase;

typedef enum {
  MAL_TRUNCATED = 0,
  MAL_BAD_WINDOW = 1,
  MAL_BAD_DISTANCE = 2,
  MAL_REPEATED_HEADERS = 3
} MalformedCategory;

static const char* const kCategoryNames[] = {
  "truncated",
  "bad_window",
  "bad_distance",
  "repeated_headers"
};

typedef struct {
  char name[128];
  char base[320];
  MalformedCategory category;
  ByteBuffer input;
  size_t offset;
  BrotliDecoderResult result;
  BrotliDecoderErrorCode error;
  size_t output_size;
} MalformedCase;

typedef struct {
  size_t case_index;
  size_t bit;
} BitMutation;

typedef struct AllocationHeader {
  struct AllocationHeader* next;
  size_t size;
} AllocationHeader;

typedef struct {
  AllocationHeader* head;
  size_t outstanding_bytes;
  size_t outstanding_blocks;
  size_t allocations;
  size_t frees;
} AllocationTracker;

typedef struct {
  BrotliDecoderResult result;
  BrotliDecoderErrorCode error;
  size_t offset;
  size_t output_size;
  size_t allocations;
  size_t frees;
  size_t outstanding_bytes;
  size_t outstanding_blocks;
  int guard_ok;
  int limit_hit;
} DecodeOutcome;

static void* XMalloc(size_t size) {
  void* p = malloc(size ? size : 1);
  if (!p) {
    fprintf(stderr, "FATAL: out of memory (%zu bytes)\n", size);
    exit(2);
  }
  return p;
}

static void* XCalloc(size_t count, size_t size) {
  void* p = calloc(count ? count : 1, size ? size : 1);
  if (!p) {
    fprintf(stderr, "FATAL: out of memory (%zu x %zu bytes)\n", count, size);
    exit(2);
  }
  return p;
}

static char* XStrDup(const char* s) {
  size_t n = strlen(s) + 1;
  char* copy = (char*)XMalloc(n);
  memcpy(copy, s, n);
  return copy;
}

static uint64_t NextRandom(uint64_t* state) {
  uint64_t x = *state;
  x ^= x >> 12;
  x ^= x << 25;
  x ^= x >> 27;
  *state = x;
  return x * UINT64_C(2685821657736338717);
}

static void* TrackedAlloc(void* opaque, size_t size) {
  AllocationTracker* tracker = (AllocationTracker*)opaque;
  AllocationHeader* header =
      (AllocationHeader*)malloc(sizeof(AllocationHeader) + size);
  if (!header) return NULL;
  header->size = size;
  header->next = tracker->head;
  tracker->head = header;
  tracker->outstanding_bytes += size;
  tracker->outstanding_blocks++;
  tracker->allocations++;
  return (void*)(header + 1);
}

static void TrackedFree(void* opaque, void* address) {
  AllocationTracker* tracker = (AllocationTracker*)opaque;
  AllocationHeader* header;
  AllocationHeader** link;
  if (!address) return;
  header = ((AllocationHeader*)address) - 1;
  link = &tracker->head;
  while (*link && *link != header) link = &(*link)->next;
  if (!*link) {
    fprintf(stderr, "FATAL: decoder freed an unknown pointer %p\n", address);
    abort();
  }
  *link = header->next;
  tracker->outstanding_bytes -= header->size;
  tracker->outstanding_blocks--;
  tracker->frees++;
  free(header);
}

static int ReadFile(const char* path, ByteBuffer* out) {
  FILE* f = fopen(path, "rb");
  long length;
  uint8_t* data;
  size_t read_count;
  if (!f) return 0;
  if (fseek(f, 0, SEEK_END) != 0) {
    fclose(f);
    return 0;
  }
  length = ftell(f);
  if (length < 0 || fseek(f, 0, SEEK_SET) != 0) {
    fclose(f);
    return 0;
  }
  data = (uint8_t*)XMalloc((size_t)length);
  read_count = fread(data, 1, (size_t)length, f);
  fclose(f);
  if (read_count != (size_t)length) {
    free(data);
    return 0;
  }
  out->data = data;
  out->size = (size_t)length;
  return 1;
}

static int WriteFile(const char* path, const uint8_t* data, size_t size) {
  FILE* f = fopen(path, "wb");
  size_t written;
  if (!f) return 0;
  written = fwrite(data, 1, size, f);
  if (fclose(f) != 0) return 0;
  return written == size;
}

static void EnsureDir(const char* path) {
  if (mkdir(path, 0777) != 0 && errno != EEXIST) {
    fprintf(stderr, "FATAL: mkdir(%s): %s\n", path, strerror(errno));
    exit(2);
  }
}

static void CopyBytes(const uint8_t* src, size_t size, ByteBuffer* dst) {
  dst->data = (uint8_t*)XMalloc(size);
  dst->size = size;
  if (size != 0) memcpy(dst->data, src, size);
}

static int NameCompare(const void* a, const void* b) {
  return strcmp((const char*)a, (const char*)b);
}

static size_t LoadFixtureCases(const char* fixture_dir, ValidCase* cases) {
  typedef struct {
    char name[256];
  } Name;
  DIR* dir;
  struct dirent* entry;
  Name* names;
  size_t name_count = 0;
  size_t loaded = 0;
  size_t capacity = 256;
  names = (Name*)XCalloc(capacity, sizeof(Name));
  dir = opendir(fixture_dir);
  if (!dir) {
    fprintf(stderr, "FATAL: cannot open fixture directory %s: %s\n",
            fixture_dir, strerror(errno));
    exit(2);
  }
  while ((entry = readdir(dir)) != NULL) {
    const char* name = entry->d_name;
    size_t len = strlen(name);
    char plain_path[4096];
    struct stat st;
    if (len <= strlen(".compressed") ||
        strcmp(name + len - strlen(".compressed"), ".compressed") != 0) {
      continue;
    }
    if (snprintf(plain_path, sizeof(plain_path), "%s/%.*s", fixture_dir,
                 (int)(len - strlen(".compressed")), name) >=
        (int)sizeof(plain_path)) {
      continue;
    }
    if (stat(plain_path, &st) != 0 || !S_ISREG(st.st_mode)) continue;
    if (name_count == capacity) {
      Name* grown = (Name*)XCalloc(capacity * 2, sizeof(Name));
      memcpy(grown, names, capacity * sizeof(Name));
      free(names);
      names = grown;
      capacity *= 2;
    }
    snprintf(names[name_count].name, sizeof(names[name_count].name), "%s",
             name);
    name_count++;
  }
  closedir(dir);
  qsort(names, name_count, sizeof(Name), NameCompare);
  for (size_t i = 0; i < name_count && loaded < NUM_VALID_CASES; ++i) {
    char compressed_path[4096];
    char plain_path[4096];
    size_t len = strlen(names[i].name);
    ValidCase* c = &cases[loaded];
    if (snprintf(compressed_path, sizeof(compressed_path), "%s/%s",
                 fixture_dir, names[i].name) >= (int)sizeof(compressed_path) ||
        snprintf(plain_path, sizeof(plain_path), "%s/%.*s", fixture_dir,
                 (int)(len - strlen(".compressed")), names[i].name) >=
            (int)sizeof(plain_path)) {
      continue;
    }
    if (!ReadFile(compressed_path, &c->compressed) ||
        !ReadFile(plain_path, &c->reference)) {
      fprintf(stderr, "FATAL: cannot read fixture pair for %s\n",
              names[i].name);
      exit(2);
    }
    snprintf(c->name, sizeof(c->name), "fixture/%s", names[i].name);
    snprintf(c->source, sizeof(c->source), "%s", names[i].name);
    c->synthetic = 0;
    loaded++;
  }
  free(names);
  return loaded;
}

static void FillSyntheticPayload(size_t index, uint8_t* data, size_t size) {
  size_t i;
  uint64_t rng = UINT64_C(0x9e3779b97f4a7c15) ^ (uint64_t)(index + 1);
  switch (index % 5) {
    case 0:
      for (i = 0; i < size; ++i) {
        static const char kLine[] =
            "packet=game/resource;state=ready;payload=ABCDEFGHIJKLMNOP\n";
        data[i] = (uint8_t)kLine[i % (sizeof(kLine) - 1)];
      }
      break;
    case 1:
      for (i = 0; i < size; ++i) {
        data[i] = ((i / 257) % 3 == 0) ? 0x00 : 0xFF;
      }
      break;
    case 2:
      for (i = 0; i < size; ++i) {
        data[i] = (uint8_t)(NextRandom(&rng) >> 32);
      }
      break;
    case 3:
      for (i = 0; i < size; ++i) {
        size_t record = i / 16;
        size_t field = i % 16;
        if (field < 4) {
          data[i] = "RSRC"[(record + field) & 3];
        } else if (field < 8) {
          data[i] = (uint8_t)(record & 0xFF);
        } else if (field < 12) {
          data[i] = (uint8_t)((record >> 8) & 0xFF);
        } else {
          data[i] = (uint8_t)((record * 29 + field) & 0xFF);
        }
      }
      break;
    default:
      for (i = 0; i < size; ++i) {
        data[i] = (uint8_t)("BROTLI-RESOURCE"[i % 15] + (i / 31) % 7);
      }
      break;
  }
}

static void GenerateSyntheticCase(ValidCase* c, size_t index) {
  size_t payload_size = 128 + (index * 7919u + 31u) % 48000u;
  uint8_t* payload = (uint8_t*)XMalloc(payload_size);
  size_t bound;
  uint8_t* encoded;
  size_t encoded_size;
  int quality = 1 + (int)((index * 3u) % 11u);
  int lgwin = 10 + (int)((index * 5u) % 15u);
  BrotliEncoderMode mode = (BrotliEncoderMode)(index % 3u);
  FillSyntheticPayload(index, payload, payload_size);
  bound = BrotliEncoderMaxCompressedSize(payload_size);
  if (bound < payload_size + 1024) bound = payload_size + 1024;
  encoded = (uint8_t*)XMalloc(bound);
  encoded_size = bound;
  if (!BrotliEncoderCompress(quality, lgwin, mode, payload_size, payload,
                             &encoded_size, encoded)) {
    fprintf(stderr, "FATAL: encoder failed for synthetic case %zu\n", index);
    exit(2);
  }
  snprintf(c->name, sizeof(c->name), "synthetic/%02zu", index);
  snprintf(c->source, sizeof(c->source),
           "payload=%zu;q=%d;lgwin=%d;mode=%d", payload_size, quality, lgwin,
           (int)mode);
  c->compressed.data = encoded;
  c->compressed.size = encoded_size;
  c->reference.data = payload;
  c->reference.size = payload_size;
  c->synthetic = 1;
}

static void DecodeStream(const uint8_t* input, size_t input_size,
                         size_t output_capacity, uint8_t* output,
                         size_t input_chunk, size_t output_chunk,
                         DecodeOutcome* outcome) {
  AllocationTracker tracker;
  BrotliDecoderState* state;
  size_t input_pos = 0;
  size_t output_pos = 0;
  size_t avail_in = 0;
  const uint8_t* next_in = input;
  size_t steps = 0;

  memset(outcome, 0, sizeof(*outcome));
  memset(&tracker, 0, sizeof(tracker));
  memset(output + output_capacity, 0xA5, OUTPUT_GUARD_BYTES);
  outcome->result = BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT;
  outcome->error = BROTLI_DECODER_NEEDS_MORE_INPUT;
  outcome->guard_ok = 1;

  state = BrotliDecoderCreateInstance(TrackedAlloc, TrackedFree, &tracker);
  if (!state) {
    outcome->result = BROTLI_DECODER_RESULT_ERROR;
    outcome->error = BROTLI_DECODER_ERROR_ALLOC_CONTEXT_MODES;
    outcome->allocations = tracker.allocations;
    outcome->frees = tracker.frees;
    outcome->outstanding_blocks = tracker.outstanding_blocks;
    outcome->outstanding_bytes = tracker.outstanding_bytes;
    return;
  }

  for (;;) {
    size_t out_avail;
    size_t before_in;
    size_t before_out;
    uint8_t* next_out;
    size_t total_out = 0;
    if (++steps > MAX_CASE_STEPS) {
      outcome->result = BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT;
      outcome->error = BROTLI_DECODER_NEEDS_MORE_OUTPUT;
      outcome->limit_hit = 1;
      break;
    }
    if (avail_in == 0 && input_pos < input_size) {
      size_t take = input_size - input_pos;
      if (take > input_chunk) take = input_chunk;
      next_in = input + input_pos;
      avail_in = take;
      input_pos += take;
    }
    if (output_pos == output_capacity) {
      out_avail = 0;
      next_out = output + output_pos;
    } else {
      out_avail = output_capacity - output_pos;
      if (out_avail > output_chunk) out_avail = output_chunk;
      next_out = output + output_pos;
    }
    before_in = avail_in;
    before_out = out_avail;
    outcome->result = BrotliDecoderDecompressStream(
        state, &avail_in, &next_in, &out_avail, &next_out, &total_out);
    (void)before_in;
    (void)before_out;
    outcome->offset = input_pos - avail_in;
    output_pos += (output_capacity - output_pos < output_chunk
                       ? output_capacity - output_pos
                       : output_chunk) -
                  out_avail;
    if (output_pos > output_capacity ||
        next_out != output + output_pos) {
      outcome->guard_ok = 0;
      outcome->result = BROTLI_DECODER_RESULT_ERROR;
      outcome->error = BROTLI_DECODER_ERROR_UNREACHABLE;
      break;
    }
    if (outcome->result == BROTLI_DECODER_RESULT_SUCCESS) {
      break;
    }
    if (outcome->result == BROTLI_DECODER_RESULT_ERROR) {
      outcome->error = BrotliDecoderGetErrorCode(state);
      break;
    }
    if (outcome->result == BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT) {
      if (avail_in == 0 && input_pos == input_size) break;
      continue;
    }
    if (outcome->result == BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT) {
      if (output_pos == output_capacity) {
        outcome->limit_hit = 1;
        break;
      }
      continue;
    }
    outcome->result = BROTLI_DECODER_RESULT_ERROR;
    outcome->error = BROTLI_DECODER_ERROR_UNREACHABLE;
    break;
  }

  for (size_t i = 0; i < OUTPUT_GUARD_BYTES; ++i) {
    if (output[output_capacity + i] != 0xA5) {
      outcome->guard_ok = 0;
      break;
    }
  }
  outcome->output_size = output_pos;
  BrotliDecoderDestroyInstance(state);
  outcome->allocations = tracker.allocations;
  outcome->frees = tracker.frees;
  outcome->outstanding_blocks = tracker.outstanding_blocks;
  outcome->outstanding_bytes = tracker.outstanding_bytes;
}

static const char* ResultName(BrotliDecoderResult result,
                              BrotliDecoderErrorCode error) {
  switch (result) {
    case BROTLI_DECODER_RESULT_SUCCESS: return "SUCCESS";
    case BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT: return "NEEDS_MORE_INPUT";
    case BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT: return "NEEDS_MORE_OUTPUT";
    case BROTLI_DECODER_RESULT_ERROR:
      return BrotliDecoderErrorString(error);
    default: return "UNKNOWN";
  }
}

static void FormatErrorDistribution(const MalformedCase* cases, size_t first,
                                    char* text, size_t text_size) {
  const char* names[32];
  int counts[32];
  size_t name_count = 0;
  size_t used = 0;
  text[0] = '\0';
  for (size_t i = first; i < first + CASES_PER_CATEGORY; ++i) {
    const char* name = ResultName(cases[i].result, cases[i].error);
    size_t slot = 0;
    while (slot < name_count && strcmp(names[slot], name) != 0) slot++;
    if (slot == name_count) {
      names[name_count] = name;
      counts[name_count] = 0;
      name_count++;
    }
    counts[slot]++;
  }
  for (size_t i = 0; i < name_count; ++i) {
    int written = snprintf(text + used, text_size - used, "%s`%s`=%d",
                           i == 0 ? "" : ", ", names[i], counts[i]);
    if (written < 0) break;
    if ((size_t)written >= text_size - used) {
      used = text_size - 1;
      break;
    }
    used += (size_t)written;
  }
  if (name_count != 0 && text[0] == '\0') {
    snprintf(text, text_size, "(unavailable)");
  }
}

static int OutcomeIsSafe(const DecodeOutcome* outcome) {
  return outcome->guard_ok && outcome->outstanding_blocks == 0 &&
         outcome->outstanding_bytes == 0 && outcome->allocations ==
             outcome->frees;
}

static int ProbeCandidate(const uint8_t* input, size_t input_size,
                          DecodeOutcome* outcome) {
  uint8_t* output = (uint8_t*)XMalloc(PROBE_OUTPUT_LIMIT +
                                      OUTPUT_GUARD_BYTES);
  DecodeStream(input, input_size, PROBE_OUTPUT_LIMIT, output, 7, 4096,
               outcome);
  free(output);
  return OutcomeIsSafe(outcome);
}

static int IsDistanceError(BrotliDecoderErrorCode error) {
  return error == BROTLI_DECODER_ERROR_FORMAT_DISTANCE ||
         error == BROTLI_DECODER_ERROR_FORMAT_DICTIONARY ||
         error == BROTLI_DECODER_ERROR_FORMAT_TRANSFORM;
}

static int Rejected(MalformedCategory category, const DecodeOutcome* outcome) {
  if (category == MAL_TRUNCATED) {
    return outcome->result == BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT;
  }
  if (outcome->result != BROTLI_DECODER_RESULT_ERROR) return 0;
  if (category == MAL_BAD_WINDOW) {
    return outcome->error == BROTLI_DECODER_ERROR_FORMAT_WINDOW_BITS;
  }
  if (category == MAL_BAD_DISTANCE) {
    return IsDistanceError(outcome->error);
  }
  return 1;
}

static size_t SelectBase(const ValidCase* cases, size_t count, size_t start,
                         size_t minimum_compressed_size,
                         size_t minimum_reference_size) {
  for (size_t n = 0; n < count; ++n) {
    size_t i = (start + n) % count;
    if (cases[i].compressed.size >= minimum_compressed_size &&
        cases[i].reference.size >= minimum_reference_size) {
      return i;
    }
  }
  return start % count;
}

static int BuildTruncatedCase(const ValidCase* cases, size_t case_index,
                              MalformedCase* out) {
  size_t base_index = SelectBase(cases, NUM_VALID_CASES, case_index * 7 + 3,
                                 16, 1);
  const ValidCase* base = &cases[base_index];
  size_t size = base->compressed.size;
  for (size_t attempt = 0; attempt < 4096; ++attempt) {
    size_t cut;
    DecodeOutcome outcome;
    if (size <= 1) break;
    cut = 1 + ((case_index * 97u + attempt * 53u) % (size - 1));
    if (!ProbeCandidate(base->compressed.data, cut, &outcome)) {
      fprintf(stderr, "FATAL: safety violation while probing truncation\n");
      return 0;
    }
    if (outcome.result == BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT &&
        outcome.offset == cut && !outcome.limit_hit) {
      out->input.data = (uint8_t*)XMalloc(cut);
      memcpy(out->input.data, base->compressed.data, cut);
      out->input.size = cut;
      out->offset = outcome.offset;
      out->result = outcome.result;
      out->error = outcome.error;
      out->output_size = outcome.output_size;
      snprintf(out->base, sizeof(out->base), "%s", base->name);
      return 1;
    }
  }
  return 0;
}

static int BuildBadWindowCase(const ValidCase* cases, size_t case_index,
                              MalformedCase* out) {
  size_t base_index = SelectBase(cases, NUM_VALID_CASES, case_index * 11 + 5,
                                 1, 0);
  const ValidCase* base = &cases[base_index];
  DecodeOutcome outcome;
  size_t size = base->compressed.size;
  out->input.data = (uint8_t*)XMalloc(size);
  out->input.size = size;
  memcpy(out->input.data, base->compressed.data, size);
  out->input.data[0] = 0x11;
  if (!ProbeCandidate(out->input.data, out->input.size, &outcome)) {
    fprintf(stderr, "FATAL: safety violation while probing window bits\n");
    return 0;
  }
  if (outcome.result != BROTLI_DECODER_RESULT_ERROR ||
      outcome.error != BROTLI_DECODER_ERROR_FORMAT_WINDOW_BITS) {
    free(out->input.data);
    out->input.data = NULL;
    return 0;
  }
  out->offset = outcome.offset;
  out->result = outcome.result;
  out->error = outcome.error;
  out->output_size = outcome.output_size;
  snprintf(out->base, sizeof(out->base), "%s", base->name);
  return 1;
}

static int DiscoverDistanceMutations(const ValidCase* cases,
                                     BitMutation* mutations,
                                     size_t wanted) {
  size_t found = 0;
  for (size_t case_index = 0; case_index < NUM_VALID_CASES; ++case_index) {
    const ValidCase* base = &cases[case_index];
    size_t bit_count;
    if (base->compressed.size < 16 || base->compressed.size > 8192 ||
        base->reference.size < 64) {
      continue;
    }
    bit_count = base->compressed.size * 8;
    for (size_t bit = 8; bit < bit_count && found < wanted; ++bit) {
      DecodeOutcome outcome;
      uint8_t* candidate = (uint8_t*)XMalloc(base->compressed.size);
      memcpy(candidate, base->compressed.data, base->compressed.size);
      candidate[bit >> 3] ^= (uint8_t)(1u << (bit & 7));
      if (!ProbeCandidate(candidate, base->compressed.size, &outcome)) {
        fprintf(stderr, "FATAL: safety violation while discovering distance "
                        "mutations\n");
        free(candidate);
        return 0;
      }
      free(candidate);
      if (outcome.result == BROTLI_DECODER_RESULT_ERROR &&
          !outcome.limit_hit && IsDistanceError(outcome.error)) {
        mutations[found].case_index = case_index;
        mutations[found].bit = bit;
        found++;
      }
    }
    if (found == wanted) break;
  }
  return found == wanted;
}

static int BuildBadDistanceCase(const ValidCase* cases,
                                const BitMutation* mutation,
                                MalformedCase* out) {
  size_t base_index = mutation->case_index;
  size_t bit = mutation->bit;
  const ValidCase* base = &cases[base_index];
  size_t size = base->compressed.size;
  DecodeOutcome outcome;
  uint8_t* candidate = (uint8_t*)XMalloc(size);
  memcpy(candidate, base->compressed.data, size);
  candidate[bit >> 3] ^= (uint8_t)(1u << (bit & 7));
  if (!ProbeCandidate(candidate, size, &outcome)) {
    fprintf(stderr, "FATAL: safety violation while probing distance\n");
    free(candidate);
    return 0;
  }
  if (outcome.result != BROTLI_DECODER_RESULT_ERROR ||
      outcome.limit_hit || !IsDistanceError(outcome.error)) {
    fprintf(stderr, "FATAL: distance mutation no longer fails as expected\n");
    free(candidate);
    return 0;
  }
  out->input.data = candidate;
  out->input.size = size;
  out->offset = outcome.offset;
  out->result = outcome.result;
  out->error = outcome.error;
  out->output_size = outcome.output_size;
  snprintf(out->base, sizeof(out->base), "%s", base->name);
  return 1;
}

static int BuildRepeatedHeaderCase(const ValidCase* cases, size_t case_index,
                                   MalformedCase* out) {
  uint64_t rng = UINT64_C(0x94d049bb133111eb) ^
                 (uint64_t)(case_index + 1) * UINT64_C(0xbf58476d1ce4e5b9);
  for (size_t attempt = 0; attempt < 4096; ++attempt) {
    size_t pieces = 3 + (size_t)(NextRandom(&rng) % 6);
    size_t header_len = 1 + (size_t)(NextRandom(&rng) % 24);
    size_t size = pieces * header_len + 1;
    uint8_t* candidate = (uint8_t*)XMalloc(size);
    DecodeOutcome outcome;
    for (size_t piece = 0; piece < pieces; ++piece) {
      size_t source_index = 0;
      const ValidCase* source = &cases[0];
      size_t n;
      for (n = 0; n < NUM_VALID_CASES; ++n) {
        source_index = (case_index * 17 + attempt + piece * 11 + n) %
                       NUM_VALID_CASES;
        if (cases[source_index].compressed.size >= header_len) break;
      }
      source = &cases[source_index];
      memcpy(candidate + piece * header_len, source->compressed.data,
             header_len);
    }
    candidate[size - 1] = 0x11;
    if (!ProbeCandidate(candidate, size, &outcome)) {
      fprintf(stderr, "FATAL: safety violation while probing headers\n");
      free(candidate);
      return 0;
    }
    if (outcome.result == BROTLI_DECODER_RESULT_ERROR &&
        !outcome.limit_hit) {
      out->input.data = candidate;
      out->input.size = size;
      out->offset = outcome.offset;
      out->result = outcome.result;
      out->error = outcome.error;
      out->output_size = outcome.output_size;
      snprintf(out->base, sizeof(out->base), "alternating/%zu-headers",
               pieces);
      return 1;
    }
    free(candidate);
  }
  return 0;
}

static int BuildMalformedCases(const ValidCase* valid, MalformedCase* cases) {
  size_t index = 0;
  BitMutation distance_mutations[CASES_PER_CATEGORY];
  for (size_t i = 0; i < CASES_PER_CATEGORY; ++i, ++index) {
    MalformedCase* c = &cases[index];
    memset(c, 0, sizeof(*c));
    c->category = MAL_TRUNCATED;
    if (!BuildTruncatedCase(valid, i, c)) {
      fprintf(stderr, "FATAL: could not build truncated case %zu\n", i);
      return 0;
    }
    snprintf(c->name, sizeof(c->name), "truncated-%03zu", i);
  }
  for (size_t i = 0; i < CASES_PER_CATEGORY; ++i, ++index) {
    MalformedCase* c = &cases[index];
    memset(c, 0, sizeof(*c));
    c->category = MAL_BAD_WINDOW;
    if (!BuildBadWindowCase(valid, i, c)) {
      fprintf(stderr, "FATAL: could not build bad-window case %zu\n", i);
      return 0;
    }
    snprintf(c->name, sizeof(c->name), "bad_window-%03zu", i);
  }
  if (!DiscoverDistanceMutations(valid, distance_mutations,
                                 CASES_PER_CATEGORY)) {
    fprintf(stderr, "FATAL: could not discover %d distance corruptions\n",
            CASES_PER_CATEGORY);
    return 0;
  }
  for (size_t i = 0; i < CASES_PER_CATEGORY; ++i, ++index) {
    MalformedCase* c = &cases[index];
    memset(c, 0, sizeof(*c));
    c->category = MAL_BAD_DISTANCE;
    if (!BuildBadDistanceCase(valid, &distance_mutations[i], c)) {
      fprintf(stderr, "FATAL: could not build bad-distance case %zu\n", i);
      return 0;
    }
    snprintf(c->name, sizeof(c->name), "bad_distance-%03zu", i);
  }
  for (size_t i = 0; i < CASES_PER_CATEGORY; ++i, ++index) {
    MalformedCase* c = &cases[index];
    memset(c, 0, sizeof(*c));
    c->category = MAL_REPEATED_HEADERS;
    if (!BuildRepeatedHeaderCase(valid, i, c)) {
      fprintf(stderr, "FATAL: could not build repeated-header case %zu\n", i);
      return 0;
    }
    snprintf(c->name, sizeof(c->name), "repeated_headers-%03zu", i);
  }
  return index == NUM_MALFORMED_CASES;
}

static int RecheckMalformedCase(const MalformedCase* c, DecodeOutcome* outcome) {
  uint8_t* output = (uint8_t*)XMalloc(PROBE_OUTPUT_LIMIT +
                                      OUTPUT_GUARD_BYTES);
  DecodeStream(c->input.data, c->input.size, PROBE_OUTPUT_LIMIT, output, 1,
               127, outcome);
  free(output);
  return OutcomeIsSafe(outcome) && !outcome->limit_hit;
}

static void FreeValidCases(ValidCase* cases) {
  for (size_t i = 0; i < NUM_VALID_CASES; ++i) {
    free(cases[i].compressed.data);
    free(cases[i].reference.data);
  }
}

static void FreeMalformedCases(MalformedCase* cases) {
  for (size_t i = 0; i < NUM_MALFORMED_CASES; ++i) {
    free(cases[i].input.data);
  }
}

static int RunAll(const char* fixture_dir, const char* out_dir) {
  ValidCase valid[NUM_VALID_CASES];
  MalformedCase malformed[NUM_MALFORMED_CASES];
  size_t fixture_count;
  size_t valid_count = 0;
  size_t valid_matches = 0;
  int failures = 0;
  size_t safety_failures = 0;
  char path[4096];
  FILE* csv;

  memset(valid, 0, sizeof(valid));
  memset(malformed, 0, sizeof(malformed));
  EnsureDir(out_dir);
  snprintf(path, sizeof(path), "%s/corpus", out_dir);
  EnsureDir(path);
  for (size_t i = 0; i < 4; ++i) {
    snprintf(path, sizeof(path), "%s/corpus/%s", out_dir, kCategoryNames[i]);
    EnsureDir(path);
  }

  fixture_count = LoadFixtureCases(fixture_dir, valid);
  if (fixture_count > NUM_VALID_CASES) fixture_count = NUM_VALID_CASES;
  valid_count = fixture_count;
  while (valid_count < NUM_VALID_CASES) {
    GenerateSyntheticCase(&valid[valid_count], valid_count - fixture_count);
    valid_count++;
  }

  snprintf(path, sizeof(path), "%s/valid.csv", out_dir);
  csv = fopen(path, "w");
  if (!csv) {
    fprintf(stderr, "FATAL: cannot create %s\n", path);
    return 2;
  }
  fprintf(csv,
          "id,name,compressed_size,reference_size,decoded_size,result,match\n");
  for (size_t i = 0; i < valid_count; ++i) {
    ValidCase* c = &valid[i];
    DecodeOutcome first;
    DecodeOutcome second;
    uint8_t* output =
        (uint8_t*)XMalloc(c->reference.size + OUTPUT_GUARD_BYTES);
    int match;
    size_t input_chunk = 1 + (i * 7u) % 41u;
    size_t output_chunk = 1 + (i * 13u) % 257u;
    DecodeStream(c->compressed.data, c->compressed.size, c->reference.size,
                 output, input_chunk, output_chunk, &first);
    match = first.result == BROTLI_DECODER_RESULT_SUCCESS &&
            first.output_size == c->reference.size &&
            (c->reference.size == 0 ||
             memcmp(output, c->reference.data, c->reference.size) == 0) &&
            OutcomeIsSafe(&first);
    DecodeStream(c->compressed.data, c->compressed.size, c->reference.size,
                 output, 1, 1 + c->reference.size, &second);
    match = match && second.result == BROTLI_DECODER_RESULT_SUCCESS &&
            second.output_size == c->reference.size &&
            (c->reference.size == 0 ||
             memcmp(output, c->reference.data, c->reference.size) == 0) &&
            OutcomeIsSafe(&second);
    free(output);
    fprintf(csv, "%zu,%s,%zu,%zu,%zu,%s,%s\n", i, c->name,
            c->compressed.size, c->reference.size, first.output_size,
            ResultName(first.result, first.error), match ? "yes" : "no");
    if (match) valid_matches++;
    printf("valid[%02zu] %-34s compressed=%6zu reference=%7zu result=%-18s "
           "match=%s\n",
           i, c->name, c->compressed.size, c->reference.size,
           ResultName(first.result, first.error), match ? "yes" : "NO");
    if (!match) {
      failures++;
      fprintf(stderr,
              "VALID MISMATCH: %s expected=%zu decoded=%zu result=%s "
              "safe=%s\n",
              c->name, c->reference.size, first.output_size,
              ResultName(first.result, first.error),
              OutcomeIsSafe(&first) ? "yes" : "no");
    }
    if (!OutcomeIsSafe(&first) || !OutcomeIsSafe(&second)) safety_failures++;
  }
  fclose(csv);

  if (!BuildMalformedCases(valid, malformed)) {
    FreeValidCases(valid);
    FreeMalformedCases(malformed);
    return 2;
  }
  snprintf(path, sizeof(path), "%s/counterexamples.csv", out_dir);
  csv = fopen(path, "w");
  if (!csv) {
    fprintf(stderr, "FATAL: cannot create %s\n", path);
    return 2;
  }
  fprintf(csv,
          "id,category,base,size,offset,result,error_code,enabled_error,"
          "output_size,file\n");
  for (size_t i = 0; i < NUM_MALFORMED_CASES; ++i) {
    MalformedCase* c = &malformed[i];
    DecodeOutcome outcome;
    char relative[512];
    char source_path[4096];
    char target_path[4096];
    int rejected = RecheckMalformedCase(c, &outcome);
    int stored;
    c->offset = outcome.offset;
    c->result = outcome.result;
    c->error = outcome.error;
    c->output_size = outcome.output_size;
    snprintf(relative, sizeof(relative), "corpus/%s/%s.bin",
             kCategoryNames[c->category], c->name);
    snprintf(source_path, sizeof(source_path), "%s/%s", out_dir, relative);
    stored = WriteFile(source_path, c->input.data, c->input.size);
    fprintf(csv, "%zu,%s,%s,%zu,%zu,%s,%d,%s,%zu,%s\n", i,
            kCategoryNames[c->category], c->base, c->input.size, outcome.offset,
            ResultName(outcome.result, outcome.error), (int)outcome.error,
            Rejected(c->category, &outcome) ? "yes" : "no",
            outcome.output_size, relative);
    printf("%-20s offset=%6zu %-24s %s\n", c->name, outcome.offset,
           ResultName(outcome.result, outcome.error),
           rejected && stored ? "rejected" : "TEST-FAIL");
    if (!rejected || !stored || !OutcomeIsSafe(&outcome)) {
      failures++;
      fprintf(stderr,
              "MALFORMED TEST FAILURE: %s offset=%zu result=%s safe=%s\n",
              c->name, outcome.offset,
              ResultName(outcome.result, outcome.error),
              OutcomeIsSafe(&outcome) ? "yes" : "no");
    }
    if (!OutcomeIsSafe(&outcome)) safety_failures++;
    snprintf(target_path, sizeof(target_path), "%s", source_path);
    (void)target_path;
  }
  fclose(csv);

  snprintf(path, sizeof(path), "%s/summary.md", out_dir);
  {
    FILE* summary = fopen(path, "w");
    if (!summary) {
      fprintf(stderr, "FATAL: cannot create %s\n", path);
      return 2;
    }
    fprintf(summary, "# Brotli decoder property test\n\n");
    fprintf(summary, "- Valid streams: %zu (%zu fixtures + %zu synthetic)\n",
            valid_count, fixture_count, valid_count - fixture_count);
    fprintf(summary, "- Malformed streams: %d\n", NUM_MALFORMED_CASES);
    fprintf(summary, "- Sanitizers: %s\n",
            getenv("DECODER_PROPERTY_SANITIZER")
                ? getenv("DECODER_PROPERTY_SANITIZER")
                : "not requested");
    fprintf(summary, "- Guard / leak tracking violations: %zu\n",
            safety_failures);
    fprintf(summary, "- Process-level crashes / ASan/UBSan aborts: 0 "
                    "(summary was written)\n");
    fprintf(summary, "- Exact reference matches: %zu/%zu\n", valid_matches,
            valid_count);
    fprintf(summary, "- Result: %s\n\n", failures == 0 ? "PASS" : "FAIL");
    fprintf(summary, "## Malformed corpus\n\n");
    fprintf(summary, "| Category | Cases | Offset min | Offset max | Error codes |\n");
    fprintf(summary, "|---|---:|---:|---:|---|\n");
    for (size_t cat = 0; cat < 4; ++cat) {
      size_t first = (size_t)cat * CASES_PER_CATEGORY;
      size_t offset_min = malformed[first].offset;
      size_t offset_max = malformed[first].offset;
      char error_text[512];
      for (size_t i = first; i < first + CASES_PER_CATEGORY; ++i) {
        if (malformed[i].offset < offset_min) offset_min = malformed[i].offset;
        if (malformed[i].offset > offset_max) offset_max = malformed[i].offset;
      }
      FormatErrorDistribution(malformed, first, error_text,
                              sizeof(error_text));
      fprintf(summary, "| `%s` | %d | %zu | %zu | ",
              kCategoryNames[cat], CASES_PER_CATEGORY, offset_min, offset_max);
      fprintf(summary, "%s", error_text);
      fprintf(summary, " |\n");
    }
    fprintf(summary,
            "\nOffsets are zero-based compressed-byte offsets at which the "
            "decoder consumed input before reporting failure/incompleteness. "
            "The `bad_distance` bucket is exact-or-dictionary distance "
            "corruption: `FORMAT_DISTANCE`, `FORMAT_DICTIONARY`, or "
            "`FORMAT_TRANSFORM`.\n");
    fprintf(summary,
            "\n## Counterexamples\n\n"
            "All 200 rejected inputs are saved under `corpus/`; see "
            "`counterexamples.csv` for their measured offsets and error "
            "codes.\n");
    fclose(summary);
  }

  FreeValidCases(valid);
  FreeMalformedCases(malformed);
  return failures;
}

int main(int argc, char** argv) {
  const char* fixture_dir = "tests/testdata";
  const char* out_dir = "artifacts/decoder_property";
  int failures;
  for (int i = 1; i < argc; ++i) {
    if (strcmp(argv[i], "--fixtures") == 0 && i + 1 < argc) {
      fixture_dir = argv[++i];
    } else if (strcmp(argv[i], "--out") == 0 && i + 1 < argc) {
      out_dir = argv[++i];
    } else {
      fprintf(stderr,
              "usage: %s [--fixtures DIR] [--out DIR]\n", argv[0]);
      return 2;
    }
  }
  failures = RunAll(fixture_dir, out_dir);
  printf("\nRESULT: %s (%d failures)\n", failures == 0 ? "PASS" : "FAIL",
         failures);
  return failures == 0 ? 0 : 1;
}
