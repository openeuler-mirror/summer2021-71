#ifndef DAEMON_COMMON_PULL_FORMAT_H
#define DAEMON_COMMON_PULL_FORMAT_H

#include <stdio.h>

enum PULL_FORMAT_TASK_STATUS {
    WAITING = 0,
    DOWNLOADING = 1,
    DOWNLOAD_COMPLETED = 2,
    EXTRACTING = 3,
    PULL_COMPLETED = 4,
    CACHED = 5,
};

struct isulad_pull_format{
  int layers_number;
  char **layer_digest;
  size_t *layer_size;
  size_t *dlnow;
  enum PULL_FORMAT_TASK_STATUS *layer_status;
  char *image_ref;
};

#endif