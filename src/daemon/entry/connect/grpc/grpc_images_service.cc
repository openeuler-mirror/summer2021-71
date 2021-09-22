/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: lifeng
 * Create: 2018-11-08
 * Description: provide grpc images functions
 ******************************************************************************/

#include "grpc_images_service.h"

#include <unistd.h>
#include <iostream>
#include <memory>
#include <new>
#include <string>

#include "isula_libutils/log.h"
#include "utils.h"
#include "grpc_server_tls_auth.h"

int ImagesServiceImpl::image_list_request_from_grpc(const ListImagesRequest *grequest,
                                                    image_list_images_request **request)
{
    size_t len = 0;
    image_list_images_request *tmpreq =
        (image_list_images_request *)util_common_calloc_s(sizeof(image_list_images_request));
    if (tmpreq == nullptr) {
        ERROR("Out of memory");
        return -1;
    }

    len = (size_t)grequest->filters_size();
    if (len == 0) {
        *request = tmpreq;
        return 0;
    }
    if (len > SIZE_MAX / sizeof(char *)) {
        ERROR("invalid filters size");
        goto cleanup;
    }

    tmpreq->filters = (defs_filters *)util_common_calloc_s(sizeof(defs_filters));
    if (tmpreq->filters == nullptr) {
        ERROR("Out of memory");
        goto cleanup;
    }

    tmpreq->filters->keys = (char **)util_common_calloc_s(len * sizeof(char *));
    if (tmpreq->filters->keys == nullptr) {
        goto cleanup;
    }
    tmpreq->filters->values = (json_map_string_bool **)util_common_calloc_s(len * sizeof(json_map_string_bool *));
    if (tmpreq->filters->values == nullptr) {
        free(tmpreq->filters->keys);
        tmpreq->filters->keys = nullptr;
        goto cleanup;
    }

    for (auto &iter : grequest->filters()) {
        tmpreq->filters->values[tmpreq->filters->len] =
            (json_map_string_bool *)util_common_calloc_s(sizeof(json_map_string_bool));
        if (tmpreq->filters->values[tmpreq->filters->len] == nullptr) {
            ERROR("Out of memory");
            goto cleanup;
        }
        if (append_json_map_string_bool(tmpreq->filters->values[tmpreq->filters->len],
                                        iter.second.empty() ? "" : iter.second.c_str(), true)) {
            free(tmpreq->filters->values[tmpreq->filters->len]);
            tmpreq->filters->values[tmpreq->filters->len] = nullptr;
            ERROR("Append failed");
            goto cleanup;
        }
        tmpreq->filters->keys[tmpreq->filters->len] = util_strdup_s(iter.first.empty() ? "" : iter.first.c_str());
        tmpreq->filters->len++;
    }
    *request = tmpreq;
    return 0;

cleanup:
    free_image_list_images_request(tmpreq);
    return -1;
}

void ImagesServiceImpl::image_list_response_to_grpc(image_list_images_response *response, ListImagesResponse *gresponse)
{
    if (response == nullptr) {
        gresponse->set_cc(ISULAD_ERR_MEMOUT);
        return;
    }

    gresponse->set_cc(response->cc);
    if (response->errmsg != nullptr) {
        gresponse->set_errmsg(response->errmsg);
    }

    for (size_t i = 0; i < response->images_len; i++) {
        Descriptor *target = nullptr;
        Image *image = gresponse->add_images();
        if (response->images[i]->name != nullptr) {
            image->set_name(response->images[i]->name);
        }
        target = new (std::nothrow) Descriptor;
        if (target == nullptr) {
            ERROR("Out of memory");
            gresponse->set_cc(ISULAD_ERR_MEMOUT);
            return;
        }
        if (response->images[i]->target->digest != nullptr) {
            target->set_digest(response->images[i]->target->digest);
        }
        Timestamp *timestamp = image->mutable_created_at();
        if (timestamp == nullptr) {
            delete target;
            gresponse->set_cc(ISULAD_ERR_MEMOUT);
            return;
        }
        timestamp->set_seconds(response->images[i]->created_at->seconds);
        timestamp->set_nanos(response->images[i]->created_at->nanos);
        if (response->images[i]->target->media_type != nullptr) {
            target->set_media_type(response->images[i]->target->media_type);
        }
        target->set_size(response->images[i]->target->size);
        image->set_allocated_target(target);
    }

    return;
}

int ImagesServiceImpl::image_remove_request_from_grpc(const DeleteImageRequest *grequest,
                                                      image_delete_image_request **request)
{
    image_delete_image_request *tmpreq =
        (image_delete_image_request *)util_common_calloc_s(sizeof(image_delete_image_request));
    if (tmpreq == nullptr) {
        ERROR("Out of memory");
        return -1;
    }

    tmpreq->force = grequest->force();
    if (!grequest->name().empty()) {
        tmpreq->image_name = util_strdup_s(grequest->name().c_str());
    }
    *request = tmpreq;

    return 0;
}

int ImagesServiceImpl::image_tag_request_from_grpc(const TagImageRequest *grequest, image_tag_image_request **request)
{
    image_tag_image_request *tmpreq = (image_tag_image_request *)util_common_calloc_s(sizeof(image_tag_image_request));
    if (tmpreq == nullptr) {
        ERROR("Out of memory");
        return -1;
    }

    if (!grequest->src_name().empty()) {
        tmpreq->src_name = util_strdup_s(grequest->src_name().c_str());
    }
    if (!grequest->dest_name().empty()) {
        tmpreq->dest_name = util_strdup_s(grequest->dest_name().c_str());
    }
    *request = tmpreq;

    return 0;
}

int ImagesServiceImpl::image_import_request_from_grpc(const ImportRequest *grequest, image_import_request **request)
{
    image_import_request *tmpreq = (image_import_request *)util_common_calloc_s(sizeof(image_import_request));
    if (tmpreq == nullptr) {
        ERROR("Out of memory");
        return -1;
    }

    if (!grequest->file().empty()) {
        tmpreq->file = util_strdup_s(grequest->file().c_str());
    }
    if (!grequest->tag().empty()) {
        tmpreq->tag = util_strdup_s(grequest->tag().c_str());
    }
    *request = tmpreq;

    return 0;
}

int ImagesServiceImpl::image_load_request_from_grpc(const LoadImageRequest *grequest,
                                                    image_load_image_request **request)
{
    image_load_image_request *tmpreq =
        (image_load_image_request *)util_common_calloc_s(sizeof(image_load_image_request));
    if (tmpreq == nullptr) {
        ERROR("Out of memory");
        return -1;
    }

    if (!grequest->file().empty()) {
        tmpreq->file = util_strdup_s(grequest->file().c_str());
    }
    if (!grequest->type().empty()) {
        tmpreq->type = util_strdup_s(grequest->type().c_str());
    }
    if (!grequest->tag().empty()) {
        tmpreq->tag = util_strdup_s(grequest->tag().c_str());
    }
    *request = tmpreq;

    return 0;
}

int ImagesServiceImpl::inspect_request_from_grpc(const InspectImageRequest *grequest, image_inspect_request **request)
{
    image_inspect_request *tmpreq = (image_inspect_request *)util_common_calloc_s(sizeof(image_inspect_request));
    if (tmpreq == nullptr) {
        ERROR("Out of memory");
        return -1;
    }

    if (!grequest->id().empty()) {
        tmpreq->id = util_strdup_s(grequest->id().c_str());
    }

    tmpreq->bformat = grequest->bformat();
    tmpreq->timeout = grequest->timeout();

    *request = tmpreq;
    return 0;
}

void ImagesServiceImpl::inspect_response_to_grpc(const image_inspect_response *response,
                                                 InspectImageResponse *gresponse)
{
    if (response == nullptr) {
        gresponse->set_cc(ISULAD_ERR_MEMOUT);
        return;
    }

    gresponse->set_cc(response->cc);
    if (response->image_json != nullptr) {
        gresponse->set_imagejson(response->image_json);
    }
    if (response->errmsg != nullptr) {
        gresponse->set_errmsg(response->errmsg);
    }
    return;
}

static int progress_to_grpc(struct isulad_pull_format *progress, 
                     PullImageProgress *gprogress) {
    if(progress->image_ref != nullptr) {
        gprogress->set_image_ref(progress->image_ref);
    } else {
        gprogress->set_layers_number(progress->layers_number);
        for(int i = 0; i < gprogress->layers_number(); i++) {
            PullImageProgress::LayerInfo *layer = gprogress->add_layers();
            layer->set_digest(progress->layer_digest[i]);
            layer->set_size(progress->layer_size[i]);
            layer->set_dlnow(progress->dlnow[i]);
            if(progress->layer_status[i] == WAITING) {
                layer->set_status(PullImageProgress::WAITING);
            } else if(progress->layer_status[i] == DOWNLOADING) {
                layer->set_status(PullImageProgress::DOWNLOADING);
            } else if(progress->layer_status[i] == DOWNLOAD_COMPLETED) {
                layer->set_status(PullImageProgress::DOWNLOAD_COMPLETED);
            } else if(progress->layer_status[i] == EXTRACTING) {
                layer->set_status(PullImageProgress::EXTRACTING);
            } else if(progress->layer_status[i] == PULL_COMPLETED) {
                layer->set_status(PullImageProgress::PULL_COMPLETED);
            } else if(progress->layer_status[i] == CACHED) {
                layer->set_status(PullImageProgress::CACHED);
            }
        }
    }
    return 0;
}

static bool grpc_progress_into_stream_write_function(void *writer, void *data) {
    struct isulad_pull_format *progress = (struct isulad_pull_format *)data;
    ServerWriter<PullImageProgress> *gwriter = (ServerWriter<PullImageProgress> *)writer;
    PullImageProgress gprogress;
    if (progress_to_grpc(progress, &gprogress) != 0) {
        return false;
    }
    fprintf(stderr, "HERE SEND A MESSAGE");
    return gwriter->Write(gprogress);
}

static int pull_request_from_grpc(const ImageSpec *image, const AuthConfig *auth, im_pull_request **request, Errors &error) 
{
    im_pull_request *tmpreq = (im_pull_request *)util_common_calloc_s(sizeof(im_pull_request));
    if (tmpreq == nullptr) {
        ERROR("Out of memory");
        error.SetError("Out of memory");
        return -1;
    }

    if (!image->image().empty()) {
        tmpreq->image = util_strdup_s(image->image().c_str());
    }

    if (!auth->username().empty()) {
        tmpreq->username = util_strdup_s(auth->username().c_str());
    }

    if (!auth->password().empty()) {
        tmpreq->password = util_strdup_s(auth->password().c_str());
    }

    if (!auth->auth().empty()) {
        tmpreq->auth = util_strdup_s(auth->auth().c_str());
    }

    if (!auth->server_address().empty()) {
        tmpreq->server_address = util_strdup_s(auth->server_address().c_str());
    }

    if (!auth->identity_token().empty()) {
        tmpreq->identity_token = util_strdup_s(auth->identity_token().c_str());
    }

    if (!auth->registry_token().empty()) {
        tmpreq->registry_token = util_strdup_s(auth->registry_token().c_str());
    }

    *request = tmpreq;

    return 0;
}

static auto DoPullImage(const ImageSpec &image, const AuthConfig &auth, Errors &error, stream_func_wrapper *stream) -> std::string
{
    std::string out_str;
    im_pull_request *request { nullptr };
    im_pull_response *response { nullptr };

    int ret = pull_request_from_grpc(&image, &auth, &request, error);
    if (ret != 0) {
        goto cleanup;
    }
    request->type = util_strdup_s(IMAGE_TYPE_OCI);

    ret = im_pull_image(request, &response, stream);
    if (ret != 0) {
        if (response != nullptr && response->errmsg != nullptr) {
            error.SetError(response->errmsg);
        } else {
            error.SetError("Failed to call pull image");
        }
        goto cleanup;
    }
    if (response->image_ref != nullptr) {
        out_str = response->image_ref;
    }
    (void)isulad_monitor_send_image_event(request->image, IM_PULL);

cleanup:
    DAEMON_CLEAR_ERRMSG();
    free_im_pull_request(request);
    free_im_pull_response(response);
    return out_str;
}

Status ImagesServiceImpl::PullImage(ServerContext *context, const PullImageRequest *request, ServerWriter<PullImageProgress> *writer)
{
    Errors error;

    EVENT("Event: {Object: CRI, Type: Pulling image %s}", request->image().image().c_str());
    
    //new stream wrapper
    stream_func_wrapper stream = { 0 }; 
    stream.writer = (void *)writer;
    stream.write_func = &grpc_progress_into_stream_write_function;

    std::string imageRef = DoPullImage(request->image(), request->auth(), error, &stream);
    if (!error.Empty() || imageRef.empty()) {
        ERROR("{Object: CRI, Type: Failed to pull image %s}", request->image().image().c_str());
        return Status(StatusCode::UNKNOWN, error.GetMessage());
    }
    
    EVENT("Event: {Object: CRI, Type: Pulled image %s with ref %s}", request->image().image().c_str(),
          imageRef.c_str());
    return Status::OK;
}

Status ImagesServiceImpl::List(ServerContext *context, const ListImagesRequest *request, ListImagesResponse *reply)
{
    auto status = GrpcServerTlsAuth::auth(context, "image_list");
    if (!status.ok()) {
        return status;
    }
    service_executor_t *cb = get_service_executor();
    if (cb == nullptr || cb->image.list == nullptr) {
        return Status(StatusCode::UNIMPLEMENTED, "Unimplemented callback");
    }

    image_list_images_request *image_req = nullptr;
    int tret = image_list_request_from_grpc(request, &image_req);
    if (tret != 0) {
        ERROR("Failed to transform grpc request");
        reply->set_cc(ISULAD_ERR_INPUT);
        return Status::OK;
    }

    image_list_images_response *image_res = nullptr;
    (void)cb->image.list(image_req, &image_res);
    image_list_response_to_grpc(image_res, reply);

    free_image_list_images_request(image_req);
    free_image_list_images_response(image_res);

    return Status::OK;
}

Status ImagesServiceImpl::Delete(ServerContext *context, const DeleteImageRequest *request, DeleteImageResponse *reply)
{
    auto status = GrpcServerTlsAuth::auth(context, "image_delete");
    if (!status.ok()) {
        return status;
    }
    service_executor_t *cb = get_service_executor();
    if (cb == nullptr || cb->image.remove == nullptr) {
        return Status(StatusCode::UNIMPLEMENTED, "Unimplemented callback");
    }

    image_delete_image_request *image_req = nullptr;
    int tret = image_remove_request_from_grpc(request, &image_req);
    if (tret != 0) {
        ERROR("Failed to transform grpc request");
        reply->set_cc(ISULAD_ERR_INPUT);
        return Status::OK;
    }

    image_delete_image_response *image_res = nullptr;
    (void)cb->image.remove(image_req, &image_res);
    response_to_grpc(image_res, reply);

    free_image_delete_image_request(image_req);
    free_image_delete_image_response(image_res);

    return Status::OK;
}

Status ImagesServiceImpl::Tag(ServerContext *context, const TagImageRequest *request, TagImageResponse *reply)
{
    auto status = GrpcServerTlsAuth::auth(context, "image_tag");
    if (!status.ok()) {
        return status;
    }
    service_executor_t *cb = get_service_executor();
    if (cb == nullptr || cb->image.tag == nullptr) {
        return Status(StatusCode::UNIMPLEMENTED, "Unimplemented callback");
    }

    image_tag_image_request *image_req = nullptr;
    int tret = image_tag_request_from_grpc(request, &image_req);
    if (tret != 0) {
        ERROR("Failed to transform grpc request");
        reply->set_cc(ISULAD_ERR_INPUT);
        return Status::OK;
    }

    image_tag_image_response *image_res = nullptr;
    (void)cb->image.tag(image_req, &image_res);
    response_to_grpc(image_res, reply);

    free_image_tag_image_request(image_req);
    free_image_tag_image_response(image_res);

    return Status::OK;
}

void ImagesServiceImpl::import_response_to_grpc(const image_import_response *response, ImportResponse *gresponse)
{
    if (response == nullptr) {
        gresponse->set_cc(ISULAD_ERR_MEMOUT);
        return;
    }

    gresponse->set_cc(response->cc);
    if (response->id != nullptr) {
        gresponse->set_id(response->id);
    }
    if (response->errmsg != nullptr) {
        gresponse->set_errmsg(response->errmsg);
    }
    return;
}

Status ImagesServiceImpl::Import(ServerContext *context, const ImportRequest *request, ImportResponse *reply)
{
    auto status = GrpcServerTlsAuth::auth(context, "image_import");
    if (!status.ok()) {
        return status;
    }
    service_executor_t *cb = get_service_executor();
    if (cb == nullptr || cb->image.import == nullptr) {
        return Status(StatusCode::UNIMPLEMENTED, "Unimplemented callback");
    }

    image_import_request *image_req = nullptr;
    int tret = image_import_request_from_grpc(request, &image_req);
    if (tret != 0) {
        ERROR("Failed to transform grpc request");
        reply->set_cc(ISULAD_ERR_INPUT);
        return Status::OK;
    }

    image_import_response *image_res = nullptr;
    (void)cb->image.import(image_req, &image_res);
    import_response_to_grpc(image_res, reply);

    free_image_import_request(image_req);
    free_image_import_response(image_res);

    return Status::OK;
}

Status ImagesServiceImpl::Load(ServerContext *context, const LoadImageRequest *request, LoadImageResponse *reply)
{
    auto status = GrpcServerTlsAuth::auth(context, "image_load");
    if (!status.ok()) {
        return status;
    }
    service_executor_t *cb = get_service_executor();
    if (cb == nullptr || cb->image.load == nullptr) {
        return Status(StatusCode::UNIMPLEMENTED, "Unimplemented callback");
    }

    image_load_image_request *image_req = nullptr;
    int tret = image_load_request_from_grpc(request, &image_req);
    if (tret != 0) {
        ERROR("Failed to transform grpc request");
        reply->set_cc(ISULAD_ERR_INPUT);
        return Status::OK;
    }

    image_load_image_response *image_res = nullptr;
    (void)cb->image.load(image_req, &image_res);
    response_to_grpc(image_res, reply);

    free_image_load_image_request(image_req);
    free_image_load_image_response(image_res);

    return Status::OK;
}

Status ImagesServiceImpl::Inspect(ServerContext *context, const InspectImageRequest *request,
                                  InspectImageResponse *reply)
{
    int tret;
    service_executor_t *cb = nullptr;
    image_inspect_request *image_req = nullptr;
    image_inspect_response *image_res = nullptr;

    Status status = GrpcServerTlsAuth::auth(context, "image_inspect");
    if (!status.ok()) {
        return status;
    }

    cb = get_service_executor();
    if (cb == nullptr || cb->image.inspect == nullptr) {
        return Status(StatusCode::UNIMPLEMENTED, "Unimplemented callback");
    }

    tret = inspect_request_from_grpc(request, &image_req);
    if (tret != 0) {
        ERROR("Failed to transform grpc request");
        reply->set_cc(ISULAD_ERR_INPUT);
        return Status::OK;
    }

    (void)cb->image.inspect(image_req, &image_res);
    inspect_response_to_grpc(image_res, reply);

    free_image_inspect_request(image_req);
    free_image_inspect_response(image_res);

    return Status::OK;
}

int ImagesServiceImpl::image_login_request_from_grpc(const LoginRequest *grequest, image_login_request **request)
{
    image_login_request *tmpreq = (image_login_request *)util_common_calloc_s(sizeof(image_login_request));
    if (tmpreq == nullptr) {
        ERROR("Out of memory");
        return -1;
    }

    if (!grequest->username().empty()) {
        tmpreq->username = util_strdup_s(grequest->username().c_str());
    }
    if (!grequest->password().empty()) {
        tmpreq->password = util_strdup_s(grequest->password().c_str());
    }
    if (!grequest->server().empty()) {
        tmpreq->server = util_strdup_s(grequest->server().c_str());
    }
    if (!grequest->type().empty()) {
        tmpreq->type = util_strdup_s(grequest->type().c_str());
    }
    *request = tmpreq;

    return 0;
}

int ImagesServiceImpl::image_logout_request_from_grpc(const LogoutRequest *grequest, image_logout_request **request)
{
    image_logout_request *tmpreq = (image_logout_request *)util_common_calloc_s(sizeof(image_logout_request));
    if (tmpreq == nullptr) {
        ERROR("Out of memory");
        return -1;
    }

    if (!grequest->server().empty()) {
        tmpreq->server = util_strdup_s(grequest->server().c_str());
    }
    if (!grequest->type().empty()) {
        tmpreq->type = util_strdup_s(grequest->type().c_str());
    }
    *request = tmpreq;

    return 0;
}

Status ImagesServiceImpl::Login(ServerContext *context, const LoginRequest *request, LoginResponse *reply)
{
    auto status = GrpcServerTlsAuth::auth(context, "login");
    if (!status.ok()) {
        return status;
    }
    service_executor_t *cb = get_service_executor();
    if (cb == nullptr || cb->image.login == nullptr) {
        return Status(StatusCode::UNIMPLEMENTED, "Unimplemented callback");
    }

    image_login_request *image_req = nullptr;
    int tret = image_login_request_from_grpc(request, &image_req);
    if (tret != 0) {
        ERROR("Failed to transform grpc request");
        reply->set_cc(ISULAD_ERR_INPUT);
        return Status::OK;
    }

    image_login_response *image_res = nullptr;
    (void)cb->image.login(image_req, &image_res);
    response_to_grpc(image_res, reply);

    free_image_login_request(image_req);
    free_image_login_response(image_res);

    return Status::OK;
}

Status ImagesServiceImpl::Logout(ServerContext *context, const LogoutRequest *request, LogoutResponse *reply)
{
    auto status = GrpcServerTlsAuth::auth(context, "logout");
    if (!status.ok()) {
        return status;
    }
    service_executor_t *cb = get_service_executor();
    if (cb == nullptr || cb->image.logout == nullptr) {
        return Status(StatusCode::UNIMPLEMENTED, "Unimplemented callback");
    }

    image_logout_request *image_req = nullptr;
    int tret = image_logout_request_from_grpc(request, &image_req);
    if (tret != 0) {
        ERROR("Failed to transform grpc request");
        reply->set_cc(ISULAD_ERR_INPUT);
        return Status::OK;
    }

    image_logout_response *image_res = nullptr;
    (void)cb->image.logout(image_req, &image_res);
    response_to_grpc(image_res, reply);

    free_image_logout_request(image_req);
    free_image_logout_response(image_res);

    return Status::OK;
}
