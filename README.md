# iOSJailbreakDetection

iOS的ObjC的app，实现越狱检测功能

## 功能介绍

主要分2部分=2个页面：

* 文件类的越狱检测 = `JbDetectOpenFileViewController`
* 其他方面的越狱检测 = `JbDetectOtherViewController`

## 检测效果举例

此处有一个越狱手机，iPhone7，下面是检测结果：

### 文件类的：JbDetectOpenFileViewController

初始化默认显示：

![file_default_1](assets/file_default_1.png)

![file_default_2](assets/file_default_2.png)

分别点击一些按钮，对应的检测出的结果，即越狱文件路径的个数：

* `stat`: `43`
  * ![file_result_43_stat](assets/file_result_43_stat.png)
* `lstat`: `8`
  * ![file_result_8_lstat](assets/file_result_8_lstat.png)
* `statfs`: `77`
  * ![file_result_77_statfs](assets/file_result_77_statfs.png)
* `opendir`: `0`
  * ![file_result_0_opendir](assets/file_result_0_opendir.png)

### 其他的：JbDetectOtherViewController

初始化默认显示：

![other_default_1](assets/other_default_1.png)

![other_default_2](assets/other_default_2.png)

分别点击一些按钮，对应的检测出的结果，即是否是越狱手机，以及异常的越狱手机才会有的动态库dylib文件的个数：

* `cydia`：是越狱手机
  * ![other_result_cydia](assets/other_result_cydia.png)
* `dlopen+dlsym`：是越狱手机，4个
  * ![other_result_dl_4](assets/other_result_dl_4.png)
* `_dyld_image_count() + _dyld_get_image_name()`：是越狱手机，5个
  * ![other_result_dyld_5](assets/other_result_dyld_5.png)
* `LSApplication`：是越狱手机，123个异常的app
  * ![other_result_lsapplication](assets/other_result_lsapplication.png)
* `objc_copyImageNames`：是越狱手机，1个
  * ![other_result_objcCopy_1](assets/other_result_objcCopy_1.png)
