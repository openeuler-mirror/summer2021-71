# OSPP中期提交-Gitlab

## branch介绍
* main分支是修改代码时基于的版本
* summer分支是至今code && push的代码，作为OSPP前半期的分支
* update分支同summer分支，准备用来做OSPP后半期的分支

## 修改过的文件 && 中期成果
* 可以翻summer分支下的commit记录具体查看修改部分
* `iSulad\docs`
    * i.md 自己读daemon部分源码做的笔记
    * build_guide_zh.md 修改了一下lcr和lxc的编译命令
    * build.me 是自己写的build guide
* `iSulad\src\daemon\modules\image\oci`
    * `registry_type.h` 在`struct layer_blob`里增添了一些信息表示
    * `registry/registry.c && registry/registry——apiv2.c` 增添了进度条信息和参数传递


## 待解决的问题
* 进度条不能再daemon代码里面直接输出，应该用grpc API传递到isula客户端再输出
* layer cache问题暂时忽略没考虑，当做completed状态处理
