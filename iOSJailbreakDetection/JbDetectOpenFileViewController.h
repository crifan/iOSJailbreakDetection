//
//  JbDetectOpenFileViewController.h
//  iOSJailbreakDetection
//
//  Created by crifan on 2021/11/8.
//

#import <UIKit/UIKit.h>

//#import <stdbool.h>
//#import <stdio.h>

#import "JailbreakPathList.h"
#import "CrifanLibDemo.h"
#import "CrifanLibiOS.h"
#import "JailbreakiOS.h"

NS_ASSUME_NONNULL_BEGIN

@interface JbDetectOpenFileViewController : UIViewController

//- (BOOL) openFile:(NSString *)filePath funcType:(OpenFileFunctionType) funcType;

- (IBAction)jbDetectFileBtnClicked:(UIButton *)sender;

@property (weak, nonatomic) IBOutlet UILabel *curClickedBtnlbl;
@property (weak, nonatomic) IBOutlet UITextView *jbPathResultListTv;

- (IBAction)openJbDetectOtherBtnClicked:(UIButton *)sender;

@end
NS_ASSUME_NONNULL_END
