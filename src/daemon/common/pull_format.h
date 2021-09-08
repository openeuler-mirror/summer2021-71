#ifndef DAEMON_COMMON_PULL_FORMAT_H
#define DAEMON_COMMON_PULL_FORMAT_H


struct isulad_pull_format{
  enum TASK_STATUS {
    WAITING = 0,
    DOWNLOADING = 1,
    DOWNLOAD_COMPLETED = 2,
    EXTRACTING = 3,
    PULL_COMPLETED = 4,
  };

  int layers_num;
  char **layer_digest;
  int *layer_size;
  int *dlnow;
  enum TASK_STATUS *layer_status;
  char *image_ref;
};

#endif