//
//  Copyright (c) 2012 Vivek Jain. All rights reserved.
//

#import <Cocoa/Cocoa.h>

@interface HeraclesAppDelegate : NSObject <NSApplicationDelegate>

@property (assign) IBOutlet NSWindow *window;
@property (weak) IBOutlet NSButton *rightButton;
@property (weak) IBOutlet NSButton *leftButton;
@property (weak) IBOutlet NSView *parentView;
@property (weak) IBOutlet NSView *securityWarningView;
@property (weak) IBOutlet NSView *loginView;
@property (weak) IBOutlet NSTextField *usernameField;
@property (weak) IBOutlet NSSecureTextField *passwordField;
@property (weak) IBOutlet NSTextField *statusLabel;

- (IBAction)rightButtonClicked:(id)sender;
- (IBAction)leftButtonClicked:(id)sender;
- (IBAction)performClose:(id)sender;

@end
