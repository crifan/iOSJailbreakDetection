//
//  JbDetectOtherViewController.h
//  iOSJailbreakDetection
//
//  Created by crifan on 2021/12/3.
//

#import <UIKit/UIKit.h>

NS_ASSUME_NONNULL_BEGIN

@interface JbDetectOtherViewController : UIViewController

@property (weak, nonatomic) IBOutlet UITextView *detectResultTv;
@property (weak, nonatomic) IBOutlet UILabel *curBtnLbl;

- (IBAction)detectCydiaBtnClicked:(UIButton *)sender;
- (IBAction)forkBtnClicked:(UIButton *)sender;
- (IBAction)syscallForkBtnClicked:(UIButton *)sender;
- (IBAction)dlopenDlsymBtnClicked:(UIButton *)sender;
- (IBAction)dladdrBtnClicked:(UIButton *)sender;
- (IBAction)dyldImgCntNameBtnClicked:(UIButton *)sender;
- (IBAction)getenvDyInsLibBtnClicked:(UIButton *)sender;
- (IBAction)systemBtnClicked:(UIButton *)sender;
- (IBAction)writeFileBtnClicked:(UIButton *)sender;
- (IBAction)sshBtnClicked:(UIButton *)sender;
- (IBAction)isDebugableBtnClicked:(UIButton *)sender;

- (IBAction)objCopyBtnClicked:(UIButton *)sender;
- (IBAction)reCodeSignBtnClicked:(UIButton *)sender;
- (IBAction)processCheckBtnClicked:(UIButton *)sender;
- (IBAction)dyldRegImgBtnClicked:(UIButton *)sender;

- (IBAction)showOpenFileOtherVc:(UIButton *)sender;
@end

NS_ASSUME_NONNULL_END
