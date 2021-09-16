/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: wujing
 * Create: 2020-12-15
 * Description: provide cri runtime versioner service function definition
 *********************************************************************************/

#ifndef DAEMON_ENTRY_CRI_RUNTIME_VERSIONER_H
#define DAEMON_ENTRY_CRI_RUNTIME_VERSIONER_H

#include <string>
#include "api.pb.h"
#include "errors.h"

namespace CRI {
class RuntimeVersionerService {
public:
    RuntimeVersionerService() = default;
    virtual ~RuntimeVersionerService() = default;

    virtual void Version(const std::string &apiVersion, runtime::v1alpha2::VersionResponse *versionResponse,
                         Errors &error) = 0;
};
} // namespace CRI

#endif // DAEMON_ENTRY_CRI_RUNTIME_VERSIONER_H