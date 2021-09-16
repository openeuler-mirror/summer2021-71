# PROGRESS-BAR-FOR-ISULAD-PULL

[TOC]

## ONLINE MEETING RECORD

### FIRST MEETING 

* 读registry模块

* 读events.c
* 根据registry apiv2协议
* daemon->modules->image->oci->registry.c
* oci->storage->overlay->apply_diff



## PROCESS TREE

### REGISTRY PULL

```
registry_pull 
|___registry_fetch 
|	|___fetch_and_parse_manifest
|	|___fetch_all
|		|___add_fetch_task---------add one task for each uncached & unstored layer
|			|___fetch_layer_in_thread---------pthread_create
|				|___fetch_layer
|					|___fetch_data
|						|___registry_request    --- in register_apiv2.c & with char *output
|							|___|http_request_buf     --- in http_request.c 
|							|___|http_request_file    --- in http_request.c
|								|___http_request
|									|___libcurl----fetch data and store it into options->output
|													|
|___register_image



```



## OUTPUT and POSSIBLE SOLUTION



login_to_registry --------> store in buffer

fetch_data ----------------> store in file







### FOR RECEIVE BUFFER   -------------- abandon

```c

fake code:

struct http_options->output = struct Buffer 

receive(struct http_options->output ) // store in Buffer

finally: char* output = strdup(struct Buffer->content)
		 outer function get the return of char* output

!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
Maybe the struct Buffer, could be transfered from outer function to inner function
```

### FOR RECEIVED FILE

```C
inner_function :
	libcurl_receive(ptr);
	fwrite(fp, ptr); 
	fflush(fp);

outer_function:
	receive = ftell(fp);
	progress = receive / total_size;
```

```
call_back_function(){
	fwrite();
	...

	read_write_mutex.write();
	*read_size = curl_easy_gerinfo(size);
	read_write_mutex.unwrite();
}

update_progress(){
	int fetch_size;
	read_write_mutex.read();
	fetch_size = *read_size;
	read_write_mutex.unread();
	get_progress(fetch_size);
}
```





## STRUCT

### BUFFER

```C
struct Buffer {
    char *contents;
    size_t bytes_used;   // received size
    size_t total_size;
};

```

### THREAD_FETCH_INFO

````c
typedef struct {
    pull_descriptor *desc;
    size_t index;
    char *blob_digest;
    char *file;
    bool use;
    bool notified;
    char *diffid;
} thread_fetch_info;
````

### PULL_DESCRIPTOR

```C

typedef struct {
    char *image_name;
    char *dest_image_name;
    char *host;
    char *name;
    char *tag;

    char *username;
    char *password;
    char *auths_dir;

    bool use_decrypted_key;
    bool cert_loaded;
    char *ca_file;
    char *cert_file;
    char *key_file;
    char *certs_dir;

    int pulling_number;
    bool cancel;
    char *errmsg;

    char *blobpath;
    char *protocol;
    bool skip_tls_verify;
    bool insecure_registry;
    char *scope;
    pthread_mutex_t challenges_mutex;
    bool challenges_mutex_inited;
    challenge challenges[CHALLENGE_MAX];
    // This is temporary field. Once http request is performed, it is cleared
    char **headers;

    char *layer_of_hold_refs;

    // Image blobs downloaded
    manifest_blob manifest;
    config_blob config;
    layer_blob *layers;
    size_t layers_len;

    bool rollback_layers_on_failure;
    bool register_layers_complete;
    // used to calc chain id
    char *parent_chain_id;
    // used to register layer
    char *parent_layer_id;
    pthread_mutex_t mutex;
    bool mutex_inited;
    pthread_cond_t cond;
    bool cond_inited;
} pull_descriptor;
```



### HTTP_GET_OPTIONS

```C

struct http_get_options {
    unsigned with_head : 1, /* if set, means write output with response HEADER */
             with_body : 1, /* if set, means write output with response BODY */
             /* if set, means set request with "Authorization:(char *)authorization" */
             with_header_auth : 1,
             /* if set, means set requst with "Content-Type: application/json" */
             with_header_json : 1,
             /* if set, means set request with "Accept:(char *)accepts" */
             with_header_accept : 1,
             /* if set, means show the process progress" */
             show_progress : 1;

    char outputtype;

    /* if set, means connnect to unix socket */
    char *unix_socket_path;

    /*
     * if outputtype is HTTP_REQUEST_STRBUF, the output is a pointer to struct Buffer
     * if outputtype is HTTP_REQUEST_FILE, the output is a pointer to a file name
     */
    void *output;

    /* http method PUT GET POST */
    void *method;
    /* body to be sent to server */
    void *input;
    size_t input_len;

    char *authorization;

    char *accepts;

    char **custom_headers;

    bool debug;
    bool ssl_verify_peer;
    bool ssl_verify_host;

    char *ca_file;
    char *cert_file;
    char *key_file;

    char *errmsg;
    int errcode;
    bool resume;

    void *progressinfo;
    progress_info_func progress_info_op;
};
```

