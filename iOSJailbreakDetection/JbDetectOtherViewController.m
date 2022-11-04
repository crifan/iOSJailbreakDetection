//
//  JbDetectOtherViewController.m
//  iOSJailbreakDetection
//
//  Created by crifan on 2021/12/3.
//

#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <fcntl.h>
#import <sys/sysctl.h>
#import <objc/runtime.h>

//#import <sys/proc_info.h>
//#import <libproc.h>

#import "JbDetectOtherViewController.h"
#import "CrifanLib.h"
#import "JailbreakPathList.h"
#import "CrifanLibDemo.h"
#import "CrifanLibiOS.h"
#import "JailbreakiOS.h"

@interface JbDetectOtherViewController ()

@end

@implementation JbDetectOtherViewController

static NSString* checkImageResult = @"未发现越狱库 -> 非越狱手机";
NSMutableArray *checkImageFoundJbLibList = NULL;

+ (void)load {
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
      checkImageFoundJbLibList = [NSMutableArray array];
      _dyld_register_func_for_add_image(_check_image);
  });
}

+ (instancetype)sharedInstance {
    static id sharedInstance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        sharedInstance = [self new];
    });
    return sharedInstance;
}

static void _check_image(const struct mach_header *header, intptr_t slide) {
    Dl_info info;
    size_t dlInfoSize = sizeof(Dl_info);
    memset(&info, 0, dlInfoSize);

    dladdr(header, &info);
    const char* curImgName = info.dli_fname;
    if(curImgName != NULL) {
        if (isJailbreakDylib(curImgName)) {
            NSString *curImgNameNs = [NSString stringWithUTF8String: curImgName];
            [checkImageFoundJbLibList addObject: curImgNameNs];
            NSString *jbLibListStr = [CrifanLibiOS nsStrListToStr:checkImageFoundJbLibList isSortList:TRUE isAddIndexPrefix:TRUE];
            checkImageResult = [NSString stringWithFormat: @"发现越狱动态库 -> 越狱手机\n%@", jbLibListStr];
            NSLog(@"%@", checkImageResult);
            // "Found Jailbreak dylib: /usr/lib/substitute-inserter.dylib -> 越狱手机"
        }
    }
    return;
}


- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view.
    
    // Make UIScrollView scrollable
    CGSize curScreenSize = UIScreen.mainScreen.bounds.size;
    NSLog(@"curScreenSize=%fx%f", curScreenSize.width, curScreenSize.height);
    CGFloat scrollWidth = curScreenSize.width;
    CGFloat scrollHeight = curScreenSize.height * 2;
    [(UIScrollView *)self.view setContentSize:CGSizeMake(scrollWidth, scrollHeight)];

    // for debug
//    testIsIntInList();
    
    // for debug
//    testRandomStr();
    
    // for debug
//    testConst();

    // for debug
//    testCustomStrstr();

    // for debug
//    testTimeDate();
}

/*
#pragma mark - Navigation

// In a storyboard-based application, you will often want to do a little preparation before navigation
- (void)prepareForSegue:(UIStoryboardSegue *)segue sender:(id)sender {
    // Get the new view controller using [segue destinationViewController].
    // Pass the selected object to the new view controller.
}
*/

- (IBAction)detectCydiaBtnClicked:(UIButton *)sender {
    _curBtnLbl.text = sender.titleLabel.text;
    NSLog(@"Clicked detect cydia://");
    BOOL canOpen = FALSE;

//    NSString *fakeCydiaStr = @"cydia://package/com.fake.packagename";
//    NSString *fakeCydiaStr = @"CYDIA://package/com.fake.packagename";
//    NSString *fakeCydiaStr = @"Cydia://package/xxx";
//    NSString *openPrefAbout = @"Prefs:root=General&path=About";
//    NSString *openPrefAbout = @"prefs:root=General&path=About";

    NSString *curToOpenStr = NULL;

//    curToOpenStr = @"weixin://";
    curToOpenStr = @"cydia://";

    NSURL *curToOpenUrl = [NSURL URLWithString:curToOpenStr];
    canOpen = [[UIApplication sharedApplication] canOpenURL:curToOpenUrl];
    NSString *canOpenStr = canOpen ? @"可以打开": @"无法打开";
    NSString *conclusionStr = canOpen ? @"可能是越狱手机": @"很可能不是越狱手机";
    NSString *resultStr = [NSString stringWithFormat:@"%@: %@\n-> %@", canOpenStr, curToOpenUrl, conclusionStr];
    NSLog(@"resultStr=%@", resultStr);
    _detectResultTv.text = resultStr;
}

- (IBAction)forkBtnClicked:(UIButton *)sender {
    _curBtnLbl.text = sender.titleLabel.text;
    NSLog(@"Fork() check");
    // SandBox Integrity Check
    int retPid = fork(); //返回值：子进程返回0，父进程中返回子进程ID，出错则返回-1
    NSString *forkResultStr = parseForkResult(retPid);
    NSLog(@"fork() return retPid=%d, forkResultStr=%@", retPid, forkResultStr);
    _detectResultTv.text = [NSString stringWithFormat:@"%@ -> %@", @"fork()", forkResultStr];
}

NSString * parseForkResult(int forkRetPid){
    NSString *forkResultStr = NULL;
    if (forkRetPid < 0){
        forkResultStr = @"无法fork->旧版iOS:非越狱, 新版iOS:无法判断";

        // log print erro info
        NSLog(@"errno=%d\n", errno);
        char *errMsg = strerror(errno);
        NSLog(@"errMsg=%s\n", errMsg);
    } else{
        forkResultStr = @"可以fork -> 旧版iOS：越狱手机";
    }

    return forkResultStr;
}

- (IBAction)syscallForkBtnClicked:(UIButton *)sender {
    _curBtnLbl.text = sender.titleLabel.text;
    NSLog(@"syscall(fork) check");
    int retPid = syscall(SYS_fork);

    NSString *forkResultStr = parseForkResult(retPid);
    NSLog(@"syscall(fork) return retPid=%d, forkResultStr=%@", retPid, forkResultStr);
    _detectResultTv.text = [NSString stringWithFormat:@"%@ -> %@", @"syscall(fork)", forkResultStr];
}

- (IBAction)dladdrBtnClicked:(UIButton *)sender {
    _curBtnLbl.text = sender.titleLabel.text;
    NSLog(@"dladdr check");

    const int DLADDR_FAILED = 0;

    const char* curSystemLib = NULL;
    char* curTestFuncName = NULL;
    Dl_info dylib_info;

    const char* SystemLib_kernel = "/usr/lib/system/libsystem_kernel.dylib";
    curSystemLib = SystemLib_kernel;
    curTestFuncName = "stat";
    int (*func_stat)(const char *, struct stat *) = stat;
    int ret = dladdr(func_stat, &dylib_info);

//    const char* SystemLib_c = "/usr/lib/system/libsystem_c.dylib";
//    curSystemLib = SystemLib_c;
//    curTestFuncName = "fopen";
//    FILE* (*func_fopen)(const char *filename, const char *mode) = fopen;
//    int ret = dladdr(func_fopen, &dylib_info);

    NSLog(@"dladdr ret=%d", ret);

    NSString *dladdrResultStr = @"";
    if (DLADDR_FAILED != ret){
        NSString* conclusionStr = @"";
        const char* libName = dylib_info.dli_fname;
        NSLog(@"dladdr dli_fname=%s, dli_fbase=%p, dli_sname=%s, dli_saddr=%p", libName, dylib_info.dli_fbase, dylib_info.dli_sname, dylib_info.dli_saddr);

        if (0 == strcmp(libName, curSystemLib)){
            conclusionStr = @"是系统库 -> 非越狱手机";
        } else {
            conclusionStr = @"不是系统库 -> 越狱手机";
        }

        dladdrResultStr = [NSString stringWithFormat:@"解析成功 -> %s 所属动态库: %s -> %@", curTestFuncName, libName, conclusionStr];
    } else{
        NSLog(@"dladdr failed: ret=%d", ret);
        dladdrResultStr = [NSString stringWithFormat:@"无法解析，返回值=%d", ret];
    }
    NSLog(@"dladdr: %@", dladdrResultStr);

    _detectResultTv.text = dladdrResultStr;
}

- (void) dbgPrintLibInfo: (int)curImgIdx{
    // debug slide
    intptr_t curSlide = _dyld_get_image_vmaddr_slide(curImgIdx);
    NSLog(@"[%d] curSlide=0x%lx", curImgIdx, curSlide);

    // debug header info
    const struct mach_header* libHeader = _dyld_get_image_header(curImgIdx);
    if (NULL != libHeader){
        int magic = libHeader->magic;
        int cputype = libHeader->cputype;
        int cpusubtype = libHeader->cpusubtype;
        int filetype = libHeader->filetype;
        int ncmds = libHeader->ncmds;
        int sizeofcmds = libHeader->sizeofcmds;
        int flags = libHeader->flags;

        NSLog(@"[%d] magic=0x%x,cputype=0x%x,cpusubtype=0x%x,filetype=%d,ncmds=%d,sizeofcmds=%d,flags=0x%x",
              curImgIdx,
              magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags);
        // 2021-12-17 09:37:46.814810+0800 iOSJailbreakDetection[11192:1067220] [0] magic=0xfeedfacf,cputype=0x100000c,cpusubtype=0x0,filetype=2,ncmds=23,sizeofcmds=3072,flags=0x200085
    } else {
        NSLog(@"[%d] mach_header is NULL", curImgIdx);
    }
}

- (IBAction)dyldImgCntNameBtnClicked:(UIButton *)sender {
    _curBtnLbl.text = sender.titleLabel.text;
    NSLog(@"_dyld_image_count and _dyld_get_image_name check");
    
//    //for debug
//    int testImgIdx = 282; // hooked:279 ~ real: 284
//    [self dbgPrintLibInfo: testImgIdx];

    uint32_t imageCount = _dyld_image_count();
    NSLog(@"dyld: imageCount=%d", imageCount);

    NSMutableArray *loadedDylibList = [NSMutableArray array];

    NSMutableArray *jbDylibList = [NSMutableArray array];
    
    for (uint32_t i = 0 ; i < imageCount; ++i) {
        const char* curImageName = _dyld_get_image_name(i);
        
        // for debug
//        bool isNeedDebug = (0 == i) || (1 == i) || (2 == i) || (275 == i);
        bool isNeedDebug = (277 == i) || (278 == i);

        if (NULL != curImageName){
            NSString *curImageNameStr = [[NSString alloc]initWithUTF8String: curImageName];
            NSLog(@"[%d] %@", i, curImageNameStr);

            [loadedDylibList addObject:curImageNameStr];

    //        if([JbPathList.jbDylibList containsObject:curImageNameStr]){
    //        if([JbPathList isJbDylib: curImageNameStr]){

            if(isJailbreakDylib(curImageName)){
                [jbDylibList addObject: curImageNameStr];

                // for debug
                isNeedDebug = true;
            }
        } else {
            NSLog(@"[%d] %s", i, curImageName);
        }

        // for debug
        if (isNeedDebug){
            [self dbgPrintLibInfo: i];
        }
    }

//    NSString *loadedDylibListStr = [CrifanLibiOS nsStrListToStr:loadedDylibList];
    NSString *loadedDylibListStr = [CrifanLibiOS nsStrListToStr:loadedDylibList isSortList:TRUE isAddIndexPrefix:TRUE];
    NSLog(@"dyld: loadedDylibListStr=%@", loadedDylibListStr);

    NSString *jbLibListStr = [CrifanLibiOS nsStrListToStr:jbDylibList isSortList:TRUE isAddIndexPrefix:TRUE];
    NSLog(@"dyld: jbDylibList=%@", jbLibListStr);

    NSString* dyldLibResultStr = @"";
    if (jbDylibList.count > 0){
        dyldLibResultStr = [NSString stringWithFormat: @"检测出越狱动态库 -> 越狱手机; 越狱动态库列表:\n%@", jbLibListStr];
    } else{
        dyldLibResultStr = @"未检测出越狱动态库 -> 非越狱手机";
    }
    NSLog(@"dyld: dyldLibResultStr=%@", dyldLibResultStr);

    _detectResultTv.text = dyldLibResultStr;
}

- (IBAction)getenvDyInsLibBtnClicked:(UIButton *)sender {
    _curBtnLbl.text = sender.titleLabel.text;
    NSLog(@"getenv(DYLD_INSERT_LIBRARIES) check");

    char* dyldPrintEnv = getenv("DYLD_PRINT_ENV");
    NSLog(@"dyldPrintEnv=%s", dyldPrintEnv);

    char* insertLibs = getenv("DYLD_INSERT_LIBRARIES");
    NSLog(@"insertLibs=%s", insertLibs);
    
    const char* dyldEnvList[] = {
        "DYLD_FRAMEWORK_PATH",
        "DYLD_FALLBACK_FRAMEWORK_PATH",
        "DYLD_VERSIONED_FRAMEWORK_PATH",
        "DYLD_LIBRARY_PATH",
        "DYLD_FALLBACK_LIBRARY_PATH",
        "DYLD_VERSIONED_LIBRARY_PATH",
        "DYLD_ROOT_PATH",
        "DYLD_SHARED_REGION",
        "DYLD_INSERT_LIBRARIES",
        "DYLD_FORCE_FLAT_NAMESPACE",
        "DYLD_IMAGE_SUFFIX",
        "DYLD_PRINT_OPTS",
        "DYLD_PRINT_ENV",
        "DYLD_PRINT_LIBRARIES",
        "DYLD_PRINT_LIBRARIES_POST_LAUNCH",
        "DYLD_BIND_AT_LAUNCH",
        "DYLD_NO_FIX_PREBINDING",
        "DYLD_DISABLE_DOFS",
        "DYLD_PRINT_APIS",
        "DYLD_PRINT_BINDINGS",
        "DYLD_PRINT_INITIALIZERS",
        "DYLD_PRINT_REBASINGS",
        "DYLD_PRINT_SEGMENTS",
        "DYLD_PRINT_STATISTICS",
        "DYLD_PRINT_DOFS",
        "DYLD_PRINT_RPATHS",
        "DYLD_SHARED_CACHE_DIR",
        "DYLD_SHARED_CACHE_DONT_VALIDATE",
    };
    const int dyldEnvListLen = sizeof(dyldEnvList)/sizeof(const char *);

    for(int curIdx = 0; curIdx < dyldEnvListLen; curIdx++){
        const char* curDyldEnv = dyldEnvList[curIdx];
        char* curEnvRet = getenv(curDyldEnv);
        NSLog(@"dyld: [%d] %s -> %s", curIdx, curDyldEnv, curEnvRet);
    }

    NSString* insertLibResultStr = @"";
    
    if (NULL != insertLibs){
        insertLibResultStr = [NSString stringWithFormat: @"检测出DYLD_INSERT_LIBRARIES -> 越狱手机; DYLD_INSERT_LIBRARIES=%s", insertLibs];
    } else{
        insertLibResultStr = @"未检测出DYLD_INSERT_LIBRARIES -> 非越狱手机";
    }
    NSLog(@"dyld: insertLibResultStr=%@", insertLibResultStr);

    _detectResultTv.text = insertLibResultStr;
}

- (IBAction)systemBtnClicked:(UIButton *)sender {
    _curBtnLbl.text = sender.titleLabel.text;
    NSLog(@"system() check");

//    int systemRet = system(NULL);
    const char* command = NULL;
//    command = "ls -lh";
//    command = "fork";
    int systemRet = iOS_system(command);

    const int SYSTEM_RET_SHELL_EXEC_CMD_FAIL = 32512; // == 0x7F00 -> bit 15-8 is 0x7F = 127
    const int SYSTEM_RET_FORK_FAIL = -1;

    NSString* conclusionStr = @"未知结果";
    if (NULL == command){
//        if (0 == systemRet){
        if (systemRet > 0){
            conclusionStr = @"sh存在 -> 越狱手机";
        } else {
            conclusionStr = @"sh不存在 -> 非越狱手机";
        }
    } else {
        if (SYSTEM_RET_SHELL_EXEC_CMD_FAIL == systemRet){
            conclusionStr = @"shell执行命令失败 -> 可能是非越狱手机";
        } else if (SYSTEM_RET_FORK_FAIL == systemRet){
            conclusionStr = @"fork或waitpid失败 -> 可能是非越狱手机";
        } else {
            conclusionStr = [NSString stringWithFormat: @"shell退出状态值为%d -> 无法判断", systemRet];
        }
    }
    NSString* systemResultStr = [NSString stringWithFormat: @"system(%s)返回: %d -> %@", command, systemRet, conclusionStr];
    NSLog(@"%@", systemResultStr);
    _detectResultTv.text = systemResultStr;
}

- (IBAction)writeFileBtnClicked:(UIButton *)sender {
    _curBtnLbl.text = sender.titleLabel.text;
    NSLog(@"write file check");

    //    NSStringEncoding strEncoding = NSStringEncodingConversionAllowLossy;
    NSStringEncoding strEncoding = NSUTF8StringEncoding;
    BOOL isAtomicWriteFile = YES;
    BOOL isUseAuxiliaryFile = NO;
    NSDataWritingOptions writeOption = NSDataWritingAtomic;

    NSString *testFile = @"/private/testWriteToFile.txt";
    // for debug
//    NSString *testFile = @"/private/var/mobile/Containers/Data/Application/EEFACEA4-2ADB-4D25-9DB4-B5D643EA8943/Documents/bd.turing/";
//    NSString *testFile = @"/private/var/mobile/Containers/Data/Application/EEFACEA4-2ADB-4D25-9DB4-B5D643EA8943/Documents/test_douyin_write.txt";
    NSString* withPrefixTestFile = [NSString stringWithFormat:@"file://%@", testFile];
    NSURL* testFileUrl = [NSURL URLWithString:withPrefixTestFile];
    NSString *testStr = @"just some test string for test write file";
    NSData* testData = [testStr dataUsingEncoding:strEncoding];

    id objects[] = { @"demo string", @123, @45.67 };
    NSUInteger count = sizeof(objects) / sizeof(id);
    NSArray *testArr = [NSArray arrayWithObjects:objects count:count];

    NSDictionary* testDict = @{
        @"intValue": @123,
        @"floatValue": @45.678,
        @"strValue": @"test write file",
    };

    NSFileManager *fileManager = [NSFileManager defaultManager];
    NSError* error = NULL;
    BOOL isWriteOk = FALSE;
    BOOL isFinalWriteOk = FALSE;

    // 1. NSString
//    // (1) [NSString writeToFile:atomically:]
//    isWriteOk = [testStr writeToFile:testFile atomically:isAtomicWriteFile];
//    NSLog(@"isWriteOk=%s", boolToStr(isWriteOk));
//    isFinalWriteOk = isWriteOk || isFinalWriteOk;

    // (2) [NSString writeToFile:atomically:encoding:error:]
    [testStr writeToFile:testFile atomically:isAtomicWriteFile encoding:strEncoding error:&error];
//    [testStr writeToFile:testFile atomically:isAtomicWriteFile encoding:strEncoding error:NULL];
    NSLog(@"isWriteOk=%s, error=%@", boolToStr(isWriteOk), error);
    isFinalWriteOk = isWriteOk || isFinalWriteOk;

    // (3) [NSString writeToURL:atomically:]
    isWriteOk = [testStr writeToURL:testFileUrl atomically:isAtomicWriteFile];
    NSLog(@"isWriteOk=%s", boolToStr(isWriteOk));
    isFinalWriteOk = isWriteOk || isFinalWriteOk;

    // (4) [NSString writeToURL:atomically:encoding:error:]
    isWriteOk = [testFile writeToURL:testFileUrl atomically:isAtomicWriteFile encoding:strEncoding error:&error];
    NSLog(@"isWriteOk=%s, error=%@", boolToStr(isWriteOk), error);
    isFinalWriteOk = isWriteOk || isFinalWriteOk;

    // 2. NSData
    // (1) [NSData writeToFile:atomically:]
    isWriteOk = [testData writeToURL:testFileUrl atomically:isAtomicWriteFile];
    NSLog(@"isWriteOk=%s", boolToStr(isWriteOk));
    isFinalWriteOk = isWriteOk || isFinalWriteOk;

    // (2) [NSData writeToFile:options:error:]
    isWriteOk = [testData writeToFile:testFile options:writeOption error:&error];
    NSLog(@"isWriteOk=%s, error=%@", boolToStr(isWriteOk), error);
    isFinalWriteOk = isWriteOk || isFinalWriteOk;

    // (3) [NSData writeToURL:atomically:]
    isWriteOk = [testData writeToURL:testFileUrl atomically:isAtomicWriteFile];
    NSLog(@"isWriteOk=%s", boolToStr(isWriteOk));
    isFinalWriteOk = isWriteOk || isFinalWriteOk;

    // (4) [NSData writeToURL:options:error:]
    isWriteOk = [testData writeToURL:testFileUrl options:writeOption error:&error];
    NSLog(@"isWriteOk=%s, error=%@", boolToStr(isWriteOk), error);
    isFinalWriteOk = isWriteOk || isFinalWriteOk;

    // 3. NSArray
    // (1) [NSArray writeToFile:atomically:]
    isWriteOk = [testArr writeToFile:testFile atomically:isUseAuxiliaryFile];
    NSLog(@"isWriteOk=%s", boolToStr(isWriteOk));
    isFinalWriteOk = isWriteOk || isFinalWriteOk;

    // (2) [NSArray writeToFile:atomically:]
    isWriteOk = [testArr writeToURL:testFileUrl atomically:isAtomicWriteFile];
    NSLog(@"isWriteOk=%s", boolToStr(isWriteOk));
    isFinalWriteOk = isWriteOk || isFinalWriteOk;

    // (3) [NSArray writeToFile:error:]
    isWriteOk = [testArr writeToURL:testFileUrl error:&error];
    NSLog(@"isWriteOk=%s, error=%@", boolToStr(isWriteOk), error);
    isFinalWriteOk = isWriteOk || isFinalWriteOk;

    // 4. NSDictionary
    // (1) [NSDictionary writeToFile:atomically:]
    isWriteOk = [testDict writeToFile:testFile atomically:isUseAuxiliaryFile];
    NSLog(@"isWriteOk=%s", boolToStr(isWriteOk));
    isFinalWriteOk = isWriteOk || isFinalWriteOk;

    // (2) [NSDictionary writeToURL:error:]
    isWriteOk = [testDict writeToURL:testFileUrl error:&error];
    NSLog(@"isWriteOk=%s, error=%@", boolToStr(isWriteOk), error);
    isFinalWriteOk = isWriteOk || isFinalWriteOk;

    // (3) [NSDictionary writeToURL:atomically:]
    isWriteOk = [testDict writeToURL:testFileUrl atomically:isAtomicWriteFile];
    NSLog(@"isWriteOk=%s", boolToStr(isWriteOk));
    isFinalWriteOk = isWriteOk || isFinalWriteOk;

//    // for debug: test removeItemAtPath
//    isWriteOk = TRUE;

    NSLog(@"isFinalWriteOk=%s", boolToStr(isFinalWriteOk));
    if (isFinalWriteOk)
    {
        NSLog(@"Ok to write file %@", testFile);
        
        BOOL isDeleteOk = FALSE;

        isDeleteOk = [fileManager removeItemAtPath:testFile error:&error];
        NSLog(@"isDeleteOk=%s, *error=%@", boolToStr(isDeleteOk), error);
//        if(error == nil){
//            isDeleteOk = TRUE;
//        }

        isDeleteOk = [fileManager removeItemAtURL:testFileUrl error:&error];
        NSLog(@"isDeleteOk=%s, *error=%@", boolToStr(isDeleteOk), error);
//        if(error == nil){
//            isDeleteOk = TRUE;
//        }

        if (isDeleteOk){
            NSLog(@"Ok to delete file %@", testFile);
        } else {
            NSLog(@"Fail to delete file %@", testFile);
        }
    } else{
        NSLog(@"Fail to write file %@", testFile);
    }
    NSString* finalResult =  @"";
    if (isFinalWriteOk){
        finalResult = @"可以写入 -> 越狱手机";
    } else {
        finalResult = @"无法写入 -> 很可能是非越狱手机";
    }
    _detectResultTv.text = finalResult;
}

- (IBAction)sshBtnClicked:(UIButton *)sender {
    _curBtnLbl.text = sender.titleLabel.text;
    NSLog(@"ssh check");
    const char* sshCmd = "ssh root@127.0.0.1";
//    int systemRet = system(sshCmd);
    int systemRet = iOS_system(sshCmd);
    NSLog(@"sshCmd=%s -> systemRet=%d", sshCmd, systemRet);
    
    _detectResultTv.text = @"TODO";
}

- (IBAction)dlopenDlsymBtnClicked:(UIButton *)sender {
    _curBtnLbl.text = sender.titleLabel.text;
    NSLog(@"dlopen + dlsym check");

    typedef void (*function_common) (void *para);
//    typedef void (*lib_MSHookFunction)(void *symbol, void *hook, void **old);

    char* dylibPathList[] = {
//        // for debug
//        "/usr/lib/libstdc++.dylib",
//        "/usr/lib/libstdc++.6.dylib",
//        "/usr/lib/libstdc++.6.0.9.dylib",

        // common: tweak plugin libs
        "/usr/lib/libsubstrate.dylib",

        // Cydia Substrate libs
        "/Library/MobileSubstrate/MobileSubstrate.dylib",
        "/usr/lib/substrate/SubstrateInserter.dylib",
        "/usr/lib/substrate/SubstrateLoader.dylib",
        "/usr/lib/substrate/SubstrateBootstrap.dylib",

        // Substitute libs
        "/usr/lib/libsubstitute.dylib",
        "/usr/lib/substitute-inserter.dylib",
        "/usr/lib/substitute-loader.dylib",

        // Other libs
        "/usr/lib/tweakloader.dylib",
    };
    const int StrSize = sizeof(const char *);
    const int DylibLen = sizeof(dylibPathList) / StrSize;
    
    char* libFuncNameList[] = {
        "MSGetImageByName",
        "MSFindSymbol",
        "MSHookFunction",
        "MSHookMessageEx",
        
        "SubGetImageByName",
        "SubFindSymbol",
        "SubHookFunction",
        "SubHookMessageEx",
    };
    const int LibFuncLen = sizeof(libFuncNameList) / StrSize;

//    NSMutableArray *detectedJbDylibList = [NSMutableArray array];
//    NSMutableArray *detectedJbFuncNameList = [NSMutableArray array];
    NSMutableArray *detectedJbLibAndFuncList = [NSMutableArray array];

    for(int libIdx = 0; libIdx < DylibLen; libIdx++) {
        char* curDylib = dylibPathList[libIdx];
        void *curLibHandle = dlopen(curDylib, RTLD_GLOBAL | RTLD_NOW);
        if (NULL == curLibHandle) {
            char* errStr = dlerror();
            NSLog(@"Failed to open dylib %s, error: %s", curDylib, errStr);
        } else {
//            NSString* curDylibNs = [NSString stringWithFormat:@"%s", curDylib];
//            [detectedJbDylibList addObject:curDylibNs];

            for(int funcIdx = 0; funcIdx < LibFuncLen; funcIdx++) {
                char* curFuncName = libFuncNameList[funcIdx];
                function_common funcInLib = dlsym(curLibHandle, curFuncName);
                if (NULL != funcInLib){
                    NSLog(@"Found func %s=%p in dylib %s\n", curFuncName, funcInLib, curDylib);

//                    NSString* curFuncNameNs = [NSString stringWithFormat:@"%s", curFuncName];
//                    [detectedJbFuncNameList addObject:curFuncNameNs];
                    NSString* curLibAndFuncNs = [NSString stringWithFormat:@"%s -> %s", curDylib, curFuncName];
                    [detectedJbLibAndFuncList addObject:curLibAndFuncNs];
                }
            }

            dlclose(curLibHandle);
        }
    }

    NSString* finalResult =  @"";
//    BOOL isJb = (detectedJbDylibList.count > 0) || (detectedJbFuncNameList.count > 0);
//    NSString *detectedJbDylibListStr = [CrifanLibiOS nsStrListToStr:detectedJbDylibList isSortList:FALSE isAddIndexPrefix:TRUE];
//    NSString *detectedJbFuncNameListStr = [CrifanLibiOS nsStrListToStr:detectedJbFuncNameList isSortList:FALSE isAddIndexPrefix:TRUE];
//    NSString* detectedLibAndFuncNameStr = [NSString stringWithFormat:@"越狱库=%@\n库函数=%@", detectedJbDylibListStr, detectedJbFuncNameListStr] ;
    
    BOOL isJb = (detectedJbLibAndFuncList.count > 0);
    NSString *detectedJbLibAndFuncListStr = [CrifanLibiOS nsStrListToStr:detectedJbLibAndFuncList isSortList:FALSE isAddIndexPrefix:TRUE];
    NSString* detectedLibAndFuncNameStr = [NSString stringWithFormat:@"越狱库和库函数=%@", detectedJbLibAndFuncListStr];

    if (isJb){
        finalResult = [NSString stringWithFormat:@"检测出越狱库或库函数 -> 越狱手机\n%@", detectedLibAndFuncNameStr] ;
    } else {
        finalResult = @"未检测出越狱库和库函数 -> 非越狱手机";
    }
    NSLog(@"finalResult=%@", finalResult);
    _detectResultTv.text = finalResult;
}

- (IBAction)isDebugableBtnClicked:(UIButton *)sender {
    _curBtnLbl.text = sender.titleLabel.text;
    NSLog(@"is debugable check");
    
//    /* tmp to debug getuid */
//    uid_t curUid = getuid();
//    NSLog(@"curUid=%d", curUid);
    
    int SYSCTL_OK = 0;
    NSString* resultStr = @"";
    BOOL isDebugable = FALSE;

    // Initialize mib, which tells sysctl the info we want, in this case
    // we're looking for information about a specific process ID.
    int name[4];             //里面放字节码。查询的信息
    name[0] = CTL_KERN;      //内核查询
    name[1] = KERN_PROC;     //查询进程
    name[2] = KERN_PROC_PID; //传递的参数是进程的ID
//    name[3] = getpid();      //获取当前进程ID
    
    int pidToCheck = -1;
    
    int currentPID = getpid();
    NSLog(@"currentPID=%d", currentPID);
    pidToCheck = currentPID;

//    //for debug
//    int parentPID = getppid();
//    NSLog(@"parentPID=%d", parentPID);
//    pidToCheck = parentPID;

    NSLog(@"pidToCheck=%d", pidToCheck);
    name[3] = pidToCheck;

    // [3]    int    13679

//    size_t infoSize = sizeof(kernelInfoProc);  // 结构体大小
    size_t infoSize = sizeof(struct kinfo_proc);
    struct kinfo_proc kernelInfoProc;  //接受查询结果的结构体
    // Initialize the flags so that, if sysctl fails for some bizarre reason, we get a predictable result.
//    kernelInfoProc.kp_proc.p_flag = 0;
    memset(&kernelInfoProc, 0, infoSize);

    // infoSize    size_t    648
//    int sysctlRet = sysctl(name, 4, &kernelInfoProc, &infoSize, 0, 0);
    int sysctlRet = sysctl(name, 4, &kernelInfoProc, &infoSize, NULL, 0);
    NSLog(@"sysctlRet=%d", sysctlRet);
    if(sysctlRet == SYSCTL_OK){
        int pFlag = kernelInfoProc.kp_proc.p_flag;
        NSLog(@"pFlag=0x%x", pFlag);
        isDebugable = ((pFlag & P_TRACED) != 0);
        NSLog(@"isDebugable=%s", boolToStr(isDebugable));
        if (isDebugable) {
            resultStr = @"可被调试 -> 越狱手机";
        } else {
            resultStr = @"不可被调试 -> 非越狱手机";
        }
    } else {
        NSLog(@"errno=%d\n", errno);
        char *errMsg = strerror(errno);
        NSLog(@"errMsg=%s\n", errMsg);
        resultStr = [NSString stringWithFormat:@"检测失败: %s", errMsg];
    }
    NSLog(@"resultStr=%@\n", resultStr);
    _detectResultTv.text = resultStr;
}

- (IBAction)objCopyBtnClicked:(UIButton *)sender {
    _curBtnLbl.text = sender.titleLabel.text;
    NSLog(@"objc_copyImageNames check");
    unsigned int outImageCount = 0;
    const char **imageList = objc_copyImageNames(&outImageCount);
    NSLog(@"outImageCount=%d, imageList=%p", outImageCount, imageList);
    
    NSMutableArray *jbImageList = [NSMutableArray array];

    if ((outImageCount > 0) && (imageList != NULL)) {
        for (int i = 0; i < outImageCount; i++) {
            const char* curImagePath = imageList[i];
            bool isJbPath = isJailbreakPath(curImagePath);
            NSLog(@"[%d] %s -> isJbPath=%s", i, curImagePath, boolToStr(isJbPath));
            if (isJbPath) {
                NSString* curImagePathNs = [NSString stringWithFormat:@"%s", curImagePath];
                [jbImageList addObject: curImagePathNs];
            }
        }
    }

    NSString *jbImageListStr = [CrifanLibiOS nsStrListToStr:jbImageList isSortList:TRUE isAddIndexPrefix:TRUE];
    NSLog(@"jbImageListStr=%@", jbImageListStr);

    NSString* resultStr = @"";
    if (jbImageList.count > 0) {
        resultStr = [NSString stringWithFormat:@"检测出越狱库image -> 越狱手机\n%@", jbImageListStr] ;
    } else {
        resultStr = @"未检测出越狱库image -> 非越狱手机";
    }
    NSLog(@"resultStr=%@", resultStr);
    _detectResultTv.text = resultStr;
}

- (IBAction)reCodeSignBtnClicked:(UIButton *)sender {
    _curBtnLbl.text = sender.titleLabel.text;
    NSLog(@"re-CodeSign check");
    NSString* resultStr = @"TODO";
    
//    NSString *embeddedPath = [[NSBundle mainBundle] pathForResource:@"embedded" ofType:@"mobileprovision"]; // embeddedPath    __NSCFString *    @"/private/var/containers/Bundle/Application/4366136E-242E-4C5D-9CC8-CF100A0B6FB2/iOSJailbreakDetection.app/embedded.mobileprovision"    0x0000000282c11830
//    if (![[NSFileManager defaultManager] fileExistsAtPath:embeddedPath]) {
//        return;
//    }

//    // 读取application-identifier  注意描述文件的编码要使用:NSASCIIStringEncoding
//    NSStringEncoding fileEncoding = NSASCIIStringEncoding;
////    NSStringEncoding fileEncoding = NSUTF8StringEncoding;
//    NSString *embeddedProvisioning = [NSString stringWithContentsOfFile:embeddedPath encoding:fileEncoding error:nil];
//    NSArray<NSString *> *embeddedProvisioningLines = [embeddedProvisioning componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]];
//    for (int i = 0; i < embeddedProvisioningLines.count; i++) {
//        if ([embeddedProvisioningLines[i] rangeOfString:@"application-identifier"].location != NSNotFound) {
//            NSString *identifierString = embeddedProvisioningLines[i + 1]; // 类似：<string>L2ZY2L7GYS.com.xx.xxx</string>
//            NSRange fromRange = [identifierString rangeOfString:@"<string>"];
//            NSInteger fromPosition = fromRange.location + fromRange.length;
//            NSInteger toPosition = [identifierString rangeOfString:@"</string>"].location;
//            NSRange range;
//            range.location = fromPosition;
//            range.length = toPosition - fromPosition;
//            NSString *fullIdentifier = [identifierString substringWithRange:range];
//            NSScanner *scanner = [NSScanner scannerWithString:fullIdentifier];
//            NSString *teamIdString;
//            [scanner scanUpToString:@"." intoString:&teamIdString];
//            NSRange teamIdRange = [fullIdentifier rangeOfString:teamIdString];
//            NSString *appIdentifier = [fullIdentifier substringFromIndex:teamIdRange.length + 1];
//            // 对比签名teamID或者identifier信息
// //           if (![appIdentifier isEqualToString:identifier] || ![teamId isEqualToString:teamIdString]) {
//            
//            if (![appIdentifier isEqualToString: curAppId]) {
//                // exit(0)
//                asm(
//                    "mov X0,#0\n"
//                    "mov w16,#1\n"
//                    "svc #0x80"
//                    );
//            }
//            break;
//        }
//    }
    
    BOOL isExistCodesign = [CrifanLibiOS isCodeSignExist];
    
    if (isExistCodesign) {
//        NSString* curAppId = @"com.crifan.iOSJailbreakDetection";
        NSString* selfAppId = @"3WRHBBSBW4.*";
        NSString* gotAddId = [CrifanLibiOS getAppId];
//        BOOL isSelfId = [CrifanLibiOS isSelfAppId: curAppId];
//        BOOL isSelfId = FALSE;
        if ([gotAddId isEqualToString: selfAppId]) {
//            isSelfId = TRUE;
            resultStr = [NSString stringWithFormat: @"embedded.mobileprovision中是自己app的ID：%@ -> 合法app", selfAppId];
        } else {
//            isSelfId = FALSE;
            resultStr = [NSString stringWithFormat: @"embedded.mobileprovision中的app的ID是%@ != 自己的AppId %@ -> 非法app", gotAddId, selfAppId];
        }
    } else {
        resultStr = @"不存在embedded.mobileprovision";
    }

    NSLog(@"resultStr=%@", resultStr);
    _detectResultTv.text = resultStr;
}
- (IBAction)lsapplicationBtnClicked:(UIButton *)sender {
    _curBtnLbl.text = sender.titleLabel.text;
    NSLog(@"LSApplication check");
    NSString* resultStr = @"TODO";

    Class LSApplicationWorkspace_class = objc_getClass("LSApplicationWorkspace");
    NSObject* workspace = [LSApplicationWorkspace_class performSelector:@selector(defaultWorkspace)];
    NSArray *allAppList = [workspace performSelector:@selector(allApplications)]; //这样就能获取到手机中安装的所有App

    resultStr = [NSString stringWithFormat: @"已安装app总数: %d", [allAppList count]];
    resultStr = [NSString stringWithFormat: @"%@\n非系统app列表：", resultStr];

    for (int i=0; i<[allAppList count]; i++) {
//        LSApplicationProxy *appProxy = [allAppList objectAtIndex:i];
//        LSApplicationProxy_class *appProxy = [allAppList objectAtIndex:i];
//        NSString* bundleId =[appProxy applicationIdentifier];
//        NSString* name = [appProxy localizedName];

        id appProxy = [allAppList objectAtIndex:i];
        NSString* bundleId =[appProxy performSelector:@selector(applicationIdentifier)];
        NSString* name = [appProxy performSelector:@selector(localizedName)];
        NSString* version = [appProxy performSelector:@selector(bundleVersion)];
        NSObject *description = [appProxy performSelector:@selector(description)];
        NSArray *plugInKitPlugins = [appProxy performSelector:@selector(plugInKitPlugins)];
        if(![bundleId hasPrefix: @"com.apple."]) {
            resultStr = [NSString stringWithFormat: @"%@\n[%d] bundleId=%@, name=%@, version=%@, description=%@, plugInKitPlugins=%@", resultStr, i, bundleId, name, version, description, plugInKitPlugins];
        }
    }

//    Class LSApplicationProxy_class = object_getClass(@"LSApplicationProxy");
//
//    for (LSApplicationProxy_class in allAppList) {
//        NSString *bundleId = [LSApplicationProxy_class performSelector:@selector(applicationIdentifier)];
//        NSString *version = [LSApplicationProxy_class performSelector:@selector(bundleVersion)];
//    }

    NSLog(@"resultStr=%@", resultStr);
    _detectResultTv.text = resultStr;
}

- (IBAction)processCheckBtnClicked:(UIButton *)sender {
    _curBtnLbl.text = sender.titleLabel.text;
    NSLog(@"process check");
    NSString* resultStr = @"TODO";

    NSArray *processes = [CrifanLibiOS runningProcesses];
    NSLog(@"processes=%@", processes);

    if (NULL == processes) {
        resultStr = @"此检测手段已失效：sysctl(CTL_KERN, KERN_PROC, KERN_PROC_ALL)";
    }

    // proc_listpids(type, typeinfo, buffer, buffersize)
    // type = PROC_ALL_PIDS, typeinfo = 0 (use proc_listallpids)
    // type = PROC_PGRP_ONLY, typeinfo = process group id (use proc_listpgrppids)
    // type = PROC_TTY_ONLY, typeinfo = tty
    // type = PROC_UID_ONLY, typeinfo = uid
    // type = PROC_RUID_ONLY, typeinfo = ruid
    // type = PROC_PPID_ONLY, typeinfo = ppid (use proc_listchildpids)
    // Call with buffer = NULL to return number of pids.
//    int numberOfProcesses = proc_listpids(PROC_ALL_PIDS, 0, NULL, 0);
//    NSLog(@"numberOfProcesses=%d", numberOfProcesses);

    NSLog(@"resultStr=%@", resultStr);
    _detectResultTv.text = resultStr;
}

- (IBAction)dyldRegImgBtnClicked:(UIButton *)sender {
    _curBtnLbl.text = sender.titleLabel.text;
    NSLog(@"dlyd register image add/remove check");
    NSString* resultStr = @"TODO";

    resultStr = checkImageResult;

    NSLog(@"resultStr=%@", resultStr);
    _detectResultTv.text = resultStr;
}

- (IBAction)showOpenFileOtherVc:(UIButton *)sender {
    UIStoryboard *storyboard = [UIStoryboard storyboardWithName:@"Main" bundle:nil];
    UIViewController *viewController = [storyboard instantiateViewControllerWithIdentifier:@"JbDetectOpenFileVc"];
    [self presentViewController:viewController animated:YES completion:nil];
}

@end
