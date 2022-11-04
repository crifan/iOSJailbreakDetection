//
//  JbDetectOpenFileViewController.m
//  iOSJailbreakDetection
//
//  Created by crifan on 2021/11/8.
//

#import "JbDetectOpenFileViewController.h"

#import "SFAntiPiracy.h"
#include <unistd.h>

@interface JbDetectOpenFileViewController ()

@end

@implementation JbDetectOpenFileViewController

/*==============================================================================
 Debug / Test
==============================================================================*/

void testSFAntiPiracy(void){
    if ([SFAntiPiracy isJailbroken] != NOTJAIL) {
        NSLog(@"is Jailbroken write");
    } else {
        NSLog(@"is NOT Jailbroken write");
    }
    
    
    if ([SFAntiPiracy isPirated] != NOTPIRATED) {
        NSLog(@"is Pirated write");
    } else {
        NSLog(@"is NOT Pirated write");
    }
    
//    [SFAntiPiracy killApplication];
}

void testGetpgrp(void){
    int pid = getpgrp();
    if (pid <0){
        NSLog(@"IS Jailbreak");
    } else {
        NSLog(@"NOT Jailbreak");
    }
}

void testOpensourceJailbreakDetectionProjects(void){
//    testSFAntiPiracy();
    
    // https://github.com/SachinSabat/CheckJailBreakDevice.git
    testGetpgrp();
}

void testJbPath(void){
//    NSArray* curCheckPathList = JbPathList.jbPathList;
////    NSArray* curCheckPathList = JbPathList.jbDylibList;
//    for(int i = 0; i < curCheckPathList.count; i++){
//        NSLog(@"[%d] %@", i, curCheckPathList[i]);
//    }
    
    const char* jsPathList[] = {
        "/not/exist/file",
        "/usr/bin/ssh",
        "/Applications/Cydia.app/../Cydia.app",
        "/./bin/../bin/./bash",
    };
    int jbPathListLen = sizeof(jsPathList)/sizeof(const char *);
    for (int i=0; i < jbPathListLen; i++) {
        const char* curJbPath = jsPathList[i];
        NSString *curJbPathNsStr = [NSString stringWithFormat:@"%s", curJbPath];
        bool isJb = [JailbreakiOS isJailbreakPath_iOS: curJbPathNsStr];
        printf("curJbPath=%s -> isJb=%s\n", curJbPath, boolToStr(isJb));
        printf("\n");
    }
}

/*==============================================================================
 Main
==============================================================================*/

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view.

    // Make UIScrollView scrollable
    CGSize curScreenSize = UIScreen.mainScreen.bounds.size;
    NSLog(@"curScreenSize=%fx%f", curScreenSize.width, curScreenSize.height);
    CGFloat scrollWidth = curScreenSize.width;
    CGFloat scrollHeight = curScreenSize.height * 2;
    [(UIScrollView *)self.view setContentSize:CGSizeMake(scrollWidth, scrollHeight)];

//    // for debug: test compare path
//    testPathCompare();

    // for debug: parse pure path
//    testParsePurePath();
    
    //for debug
//    testJbPathDetect();
    
    //for debug
//    testLowcase();
    
    // for debug
//    testJbPath();
    
    // for debug
//    testPathJoin();
    
    // for debug
//    testOpensourceJailbreakDetectionProjects();
}

/*
#pragma mark - Navigation

// In a storyboard-based application, you will often want to do a little preparation before navigation
- (void)prepareForSegue:(UIStoryboardSegue *)segue sender:(id)sender {
    // Get the new view controller using [segue destinationViewController].
    // Pass the selected object to the new view controller.
}
*/

//- (IBAction)jbDetectFileStatBtnClicked:(UIButton *)sender {
- (IBAction)jbDetectFileBtnClicked:(UIButton *)sender{
    NSString *curBtnName = sender.titleLabel.text;
    NSLog(@"Clicked detect jailbreak file button: %@", curBtnName);

    _curClickedBtnlbl.text = curBtnName;

    int senderTag = (int)sender.tag;
    OpenFileFunctionType curFuncType = FUNC_UNKNOWN;
    if (senderTag == BTN_STAT){
        curFuncType = FUNC_STAT;
    } else if (senderTag == BTN_STAT64){
        curFuncType = FUNC_STAT64;
    } else if (senderTag == BTN_SYSCALL_STAT){
        curFuncType = FUNC_SYSCALL_STAT;
    } else if (senderTag == BTN_SYSCALL_STAT64){
        curFuncType = FUNC_SYSCALL_STAT64;
    } else if (senderTag == BTN_SYSCALL_LSTAT){
        curFuncType = FUNC_SYSCALL_LSTAT;
    } else if (senderTag == BTN_SYSCALL_FSTAT){
        curFuncType = FUNC_SYSCALL_FSTAT;
    } else if (senderTag == BTN_SYSCALL_FSTATAT){
        curFuncType = FUNC_SYSCALL_FSTATAT;
    } else if (senderTag == BTN_SYSCALL_STATFS){
        curFuncType = FUNC_SYSCALL_STATFS;
    } else if (senderTag == BTN_SYSCALL_FSTATFS){
        curFuncType = FUNC_SYSCALL_FSTATFS;
    } else if (senderTag == BTN_SVC_0X80_STAT){
        curFuncType = FUNC_SVC_0X80_STAT;
    } else if (senderTag == BTN_SVC_0X80_STAT64){
        curFuncType = FUNC_SVC_0X80_STAT64;
    } else if (senderTag == BTN_OPEN){
        curFuncType = FUNC_OPEN;
    } else if (senderTag == BTN_SYSCALL_OPEN){
        curFuncType = FUNC_SYSCALL_OPEN;
    } else if (senderTag == BTN_SYSCALL_FOPEN){
        curFuncType = FUNC_SYSCALL_FOPEN;
    } else if (senderTag == BTN_SVC_0X80_OPEN){
        curFuncType = FUNC_SVC_0X80_OPEN;
    } else if (senderTag == BTN_FOPEN){
        curFuncType = FUNC_FOPEN;
    } else if (senderTag == BTN_NSFILEMANAGER){
        curFuncType = FUNC_NSFILEMANAGER;
    } else if (senderTag == BTN_ACCESS){
        curFuncType = FUNC_ACCESS;
    } else if (senderTag == BTN_SYSCALL_ACCESS){
        curFuncType = FUNC_SYSCALL_ACCESS;
    } else if (senderTag == BTN_FACCESSAT){
        curFuncType = FUNC_FACCESSAT;
    } else if (senderTag == BTN_SYSCALL_FACCESSAT){
        curFuncType = FUNC_SYSCALL_FACCESSAT;
    } else if (senderTag == BTN_LSTAT){
        curFuncType = FUNC_LSTAT;
    } else if (senderTag == BTN_FSTATAT){
        curFuncType = FUNC_FSTATAT;
    } else if (senderTag == BTN_STATFS){
        curFuncType = FUNC_STATFS;
    } else if (senderTag == BTN_STATFS64){
        curFuncType = FUNC_STATFS64;
    } else if (senderTag == BTN_FSTATFS){
        curFuncType = FUNC_FSTATFS;
    } else if (senderTag == BTN_FSTAT){
        curFuncType = FUNC_FSTAT;
    } else if (senderTag == BTN_REALPATH){
        curFuncType = FUNC_REALPATH;
    } else if (senderTag == BTN_OPENDIR){
        curFuncType = FUNC_OPENDIR;
    } else if (senderTag == BTN___OPENDIR2){
        curFuncType = FUNC___OPENDIR2;
    } else if (senderTag == BTN_NSURL){
        curFuncType = FUNC_NSURL;
    }
    NSLog(@"Jailbreak detect file button clicked: sender.tag=%d, curFuncType=%ld", senderTag, (long)curFuncType);

    NSMutableArray *openableJbPathList = [NSMutableArray array];
    NSLog(@"openableJbPathList=%@", openableJbPathList);

    NSArray* curCheckPathList = JailbreakiOS.jbPathList;
//    // for debug
//    NSArray* curCheckPathList = @[];

//    //for debug
//    NSArray* curCheckPathList = @[
//        // for debug: stat64 >2G file
//        @"/var/root/test_stat64/stat64_3G_truncate.txt",
//        @"/Applications/stat64_3G_truncate.txt",
//
//        // for debug: other path
//        @"/Library/LaunchDaemons/",
//
//        // for debug: test svc 0x80 for stat and stat64
//        @"/Applications/Activator.app", // Failed
//        @"/Applications/Cydia.app", // OK
//        @"/Applications/stat64_3G_truncate.txt", // > 2G
//    ];

    // for debug: tmp disable
    for(NSString* curToCheckPath in curCheckPathList){
        NSLog(@"curToCheckPath=%@", curToCheckPath);
        BOOL isOpenOk = [CrifanLibiOS openFile:curToCheckPath funcType:curFuncType];
        if (isOpenOk){
            [openableJbPathList addObject:curToCheckPath];
        } else {
            NSLog(@"Failed to open file: %@", curToCheckPath);
        }
    }
    NSLog(@"openableJbPathList=%@", openableJbPathList);

    NSString *openableJbPathListStr = [CrifanLibiOS nsStrListToStr:openableJbPathList isSortList:FALSE isAddIndexPrefix:TRUE];
    _jbPathResultListTv.text = openableJbPathListStr;

//    // for debug
//    [curCheckPathList release];

    [openableJbPathList removeAllObjects];
}

- (IBAction)openJbDetectOtherBtnClicked:(UIButton *)sender {
    UIStoryboard *storyboard = [UIStoryboard storyboardWithName:@"Main" bundle:nil];
    UIViewController *viewController = [storyboard instantiateViewControllerWithIdentifier:@"JbDetectOtherVc"];
    [self presentViewController:viewController animated:YES completion:nil];
}

@end
