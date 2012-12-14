//
//  Copyright (c) 2012 Vivek Jain. All rights reserved.
//

#import <Growl/Growl.h>
#import "HeraclesAppDelegate.h"
#import "Reachability.h"
#import "Timer.h"
#import <Security/Security.h>
#import <Kerberos/Kerberos.h>
#import <QuartzCore/QuartzCore.h>
#import "PFMoveApplication.h"

#define KEYCHAIN_SERVICE_NAME "Heracles"

// Passing a URL to `TLDEXTRACT_URL` returns a JSON that contains the domain, subdomain and tld of the URL
#define TLDEXTRACT_URL @"http://tldextract.appspot.com/api/extract?url="


@implementation HeraclesAppDelegate {
    Reachability *reachability;
    BOOL exitAfterNotify; /* If true, the `notify:` method will exit after
                             notifying. This is useful when Heracles is in the
                             background and there is an error while obtaining
                             tickets, in which case Heracles does not need to
                             keep running. */
    BOOL firstRun; // True if the user has not set up Heracles yet
    NSString *username; // Stores cached Kerberos principal
    NSString *realmName; // Stores Kerberos realm
    CATransition *transition;
}

@synthesize window, rightButton, leftButton, parentView, securityWarningView, loginView, usernameField, passwordField, statusLabel;

- (void)applicationDidFinishLaunching:(NSNotification *)aNotification {
    PFMoveToApplicationsFolderIfNecessary();
    transition = [CATransition animation];
    [transition setType:kCATransitionPush];
    [transition setSubtype:kCATransitionFromRight];
    [parentView setAnimations:@{@"subviews": transition}];
    reachability = [Reachability reachabilityWithHostname:@"www.google.com"];
    [[NSNotificationCenter defaultCenter] addObserver:self 
                                             selector:@selector(authenticateInBackgroundWithNotification:)
                                                 name:kReachabilityChangedNotification 
                                               object:nil];
    
    /*
     * Since `LSUIElement` is set to true, it seems that the Heracles will not
     * be the topmost app when launched, so activate it manually (but only if
     * the window is visible, i.e. it is not being run as a hidden login
     * item).
     */
    if ([window isVisible]) {
         /*
          * When run in XCode, for some reason the window doesn't become
          * topmost if `[NSApp activateIgnoringOtherApps:YES]` is called
          * immediately, so call it with a timer to allow the application to
          * initialize before becoming frontmost.
          */
        [NSTimer scheduledTimerWithTimeInterval:0 target:self selector:@selector(activate) userInfo:nil repeats:NO];
    }
    
    username = [[NSUserDefaults standardUserDefaults] stringForKey:@"username"];
    if (username == nil) {
        [parentView addSubview:securityWarningView];
        DLOG(@"First run!");
        firstRun = YES;
        if (![window isVisible]) [window makeKeyAndOrderFront:self];
    } else {
        [parentView addSubview:loginView];
        firstRun = NO;
        [usernameField setStringValue:username];
        [leftButton setHidden:NO];
        [rightButton setTitle:@"Save"];
        NSString *password = [self getPassword];
        if (password == nil) {
            NSString *status = [NSString stringWithFormat: @"Could not retrieve password for %@.", username];
            if ([window isVisible]) [self setStatus:status error:YES];
            else [self notify:status];
        }
        else {
            [passwordField setStringValue:password];
            if (![window isVisible]) [self notify:[self authenticateWithUsername:username withPassword:password isInBackground:YES]];
            else {
                [self setStatus:@"Checking…" error:NO];
                [self performSelector:@selector(authenticateInForegroundWithPassword:) withObject:password afterDelay:1]; // Run after 1 second since doing it immediately seems to lock up the window and make it take a long time to display
            }
        }
    }
}

- (void)activate {
    [NSApp activateIgnoringOtherApps:YES];
}

/*
 * Activates the main window when the application is reopened.
 */
- (BOOL)applicationShouldHandleReopen:(NSApplication *)app hasVisibleWindows:(BOOL)flag {
    [NSApp activateIgnoringOtherApps:YES];
    [window makeKeyAndOrderFront:self];
    return NO;
}

- (IBAction)rightButtonClicked:(id)sender {
    if ([[rightButton title] isEqualToString:@"Continue"]) [self switchToLoginView];
    else {
        [self setStatus:@"Checking…" error:NO];
        if (firstRun) {
            if (![self checkPasswordOnSleep]) {
                [self setStatus:@"" error:NO];
                return;
            }
        }
        
        NSString *usernameToUse = [usernameField stringValue];
        NSString *passwordToUse = [passwordField stringValue];
        NSString *message = [self authenticateWithUsername:usernameToUse withPassword:passwordToUse isInBackground:NO];
        if (![self isSuccessfulMessage:message]) {
            [self setStatus:message error:YES];
            return;
        }
        
        [[NSUserDefaults standardUserDefaults] setObject:usernameToUse forKey:@"username"];
        username = usernameToUse;
        OSStatus status = [self setPassword:passwordToUse forUsername:usernameToUse];
        if (status != noErr) {
            NSString *errorStr = CFBridgingRelease(SecCopyErrorMessageString(status, NULL));
            NSLog(@"Error saving password: %d: %@", status, errorStr);
            [self setStatus:[NSString stringWithFormat:@"Error saving password: %@.", errorStr] error:YES];
            return;
        }
        
#ifndef DEBUG
        [self addToLoginItems];
#endif
        
        NSString *whitelist = [self getWhitelistURL];
        BOOL chromeWhitelisted;
        if ([self whitelistURL:whitelist isChromeWhitelisted:&chromeWhitelisted]) [[NSUserDefaults standardUserDefaults] setObject:whitelist forKey:@"whitelist"];

        if (firstRun) {
            firstRun = NO;
            [rightButton setStringValue:@"Save"];
        }
        [self setStatus:@"" error:NO];
        if (firstRun) message = [message stringByAppendingString:@" From now on Heracles will automatically obtain Kerberos tokens for you on login."];
        [self notify:message];
        if (chromeWhitelisted) [self alertToLogout];
        [NSApp hide:nil];
    }
}

/*
 * Hides the window when it is closed, instead of actually closing it, so that
 * it can be reopened when the application is reactivated. 
 */
- (BOOL)windowShouldClose:(id)sender {
    [NSApp hide:nil];
    return NO;
}

/*
 * Switches from the security warning view to the login view.
 */
- (void)switchToLoginView {
    if (firstRun) [rightButton setTitle:@"Enable"];
    else [rightButton setTitle:@"Save"];
    
    [leftButton setHidden:NO];
    [transition setSubtype:kCATransitionFromRight];
    [[parentView animator] replaceSubview:securityWarningView with:loginView];
    [usernameField becomeFirstResponder];
}

/*
 * Sets the string shown by `statusLabel` and forces it to redisplay.
 * `statusLabel` will be red if `error` is true, black otherwise.
 */
- (void)setStatus:(NSString *)status error:(BOOL)error {
    if (error) [statusLabel setTextColor:[NSColor redColor]];
    else [statusLabel setTextColor:[NSColor blackColor]];
    [statusLabel setStringValue:status];
    [statusLabel display];
}

/*
 * If the user has not enabled password on sleep, brings up an alert asking
 * them if they want to continue, and returns their response. Otherwise
 * returns YES.
 */
- (BOOL)checkPasswordOnSleep {
    NSDictionary *prefs=[[NSUserDefaults standardUserDefaults] persistentDomainForName:@"com.apple.screensaver"];
    if (![[prefs objectForKey:@"askForPassword"] boolValue]) {
        NSAlert *alert = [NSAlert alertWithMessageText:@"You have not required a password after sleep."
                                         defaultButton:@"Yes"
                                       alternateButton:@"No"
                                           otherButton:nil
                             informativeTextWithFormat:@"You can change this option in System Preferences → Security & Privacy → General → Require password. Are you sure you want to continue?"];
        [[[alert buttons] objectAtIndex:1] setKeyEquivalent:@"\E"];
        return [alert runModal] == NSAlertDefaultReturn;
    }
    return YES;
}

/*
 * Adds Heracles to login items, and enables hiding the window when logging in.
 * This won't do anything if Heracles is already a login item.
 */
- (void)addToLoginItems {
    LSSharedFileListRef loginItemsRef = LSSharedFileListCreate(NULL, kLSSharedFileListSessionLoginItems, NULL);
    if (loginItemsRef != NULL) {
        CFURLRef appUrl = (__bridge_retained CFURLRef)[NSURL fileURLWithPath:[[NSBundle mainBundle] bundlePath]];
        CFMutableDictionaryRef inPropertiesToSet = CFDictionaryCreateMutable(NULL, 1, NULL, NULL);
        CFDictionaryAddValue(inPropertiesToSet, kLSSharedFileListLoginItemHidden, kCFBooleanTrue); // Hide window when logging in
        LSSharedFileListItemRef itemRef = LSSharedFileListInsertItemURL(loginItemsRef, kLSSharedFileListItemLast, NULL, NULL, appUrl, inPropertiesToSet, NULL);
        if (itemRef) CFRelease(itemRef);
        else NSLog(@"Error adding Heracles to login items");
        CFRelease(inPropertiesToSet);
        CFRelease(appUrl);
        CFRelease(loginItemsRef);
    } else NSLog(@"Error getting login items");
}

/*
 * Whitelists the URL `whitelist` (if it hasn't been previously whitelisted) by
 * adding it to the user's ssh config file as a host for which Kerberos
 * authentication and delegation should be enabled. If Google Chrome is the
 * default browser, also enables Kerberos for Chrome for the given URL, and
 * sets `chromeWhitelisted` to true if this was successful. Returns whether
 * whitelisting the URL was successful.
 */
- (BOOL)whitelistURL:(NSString *)whitelist isChromeWhitelisted:(BOOL *)chromeWhitelisted {
    *chromeWhitelisted = NO;
    BOOL success = NO;
    
    if (whitelist != nil) {
        NSString *prevWhitelist = [[NSUserDefaults standardUserDefaults] stringForKey:@"whitelist"];
        if (prevWhitelist == nil || ![whitelist isEqualToString:prevWhitelist]) {
            success = YES;
            NSLog(@"%@ will be whitelisted.", whitelist);
            [self setStatus:[NSString stringWithFormat:@"Whitelisting the URL %@", whitelist] error:NO];
            
            if (![self whitelistURLForSSH:whitelist]) success = NO;

            if ([CFBridgingRelease(LSCopyDefaultHandlerForURLScheme((CFStringRef)@"http")) isEqualToString:@"com.google.chrome"]) {
                if (![self whitelistURLForChrome:whitelist]) success = NO;
                else *chromeWhitelisted = YES;
            }
        }
    }
    return success;
}

/*
 * Returns the URL that should be whitelisted, based on the user's current
 * Kerberos realm. The realm of the user's Kerberos username (converted to
 * lowercase) is sent as the argument to `TLDEXTRACT_URL`, and the domain and
 * tld of the returned JSON are combined and then prepended with the
 * subdomain `*`. For example if the realm is `KERBEROS.EXAMPLE.COM`, this
 * function would return `*.example.com` as the URL to whitelist. Returns
 * `nil` in the case of an error.
 */
- (NSString *)getWhitelistURL {
    if (realmName == nil) {
        NSLog(@"No URL whitelisted: could not find realm name");
        return nil;
    }
    if ([realmName isEqualToString:@"stanford.edu"]) return @"*.stanford.edu";
    NSURL *url = [NSURL URLWithString:[NSString stringWithFormat:TLDEXTRACT_URL @"%@", [realmName lowercaseString]]];
    NSError *error;
    NSData *data = [NSData dataWithContentsOfURL:url options:kNilOptions error:&error];
    if (error != nil) {
		NSLog(@"Error downloading JSON from %@: %@", url, error);
		return nil;
	}
    DLOG(@"Data from %@: %@", url, [NSString stringWithUTF8String:[data bytes]]);
    NSDictionary *json = [NSJSONSerialization JSONObjectWithData:data options:kNilOptions error:&error];
    if (error != nil) {
		NSLog(@"Error initializing JSON from %@: %@", [NSString stringWithUTF8String:[data bytes]], error);
		return nil;
	}
    if ([[json objectForKey:@"domain"] isEqualToString:@""] || [[json objectForKey:@"tld"]  isEqualToString:@""]) {
        NSLog(@"Error: realm name %@ does not have a domain or a tld: %@", realmName, json);
        return nil;
    }
    NSString *whitelist = [NSString stringWithFormat:@"*.%@.%@", [json objectForKey:@"domain"], [json objectForKey:@"tld"]];
    return whitelist;
}

/*
 * Adds `whitelist` to the user's ssh config file as a host for which Kerberos
 * authentication and delegation should be enabled. Returns whether writing
 * to the ssh config file was a success.
 */
- (BOOL)whitelistURLForSSH:(NSString *)whitelist {
    NSString *sshConfigPath = [NSHomeDirectory() stringByAppendingString:@"/.ssh/config"];
    DLOG(@"Writing to %@", sshConfigPath);
    NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:sshConfigPath];
    NSString *prefix = @"\n\n";
    if (fh == nil) {
        prefix = @"";
        if (![[NSFileManager defaultManager] createDirectoryAtPath:[sshConfigPath stringByDeletingLastPathComponent] withIntermediateDirectories:YES attributes:nil error:nil] ||
            ![[NSFileManager defaultManager] createFileAtPath:sshConfigPath contents:nil attributes:nil]) {
            NSLog(@"Error creating file at %@", sshConfigPath);
            return NO;
        }
        else fh = [NSFileHandle fileHandleForWritingAtPath:sshConfigPath];
    }
    if (fh == nil) {
        NSLog(@"Error opening file %@ after it was created", sshConfigPath);
        return NO;
    }
    
    NSString *toWrite = [prefix stringByAppendingFormat:@"# Beginning of Heracles autoconfigured section\n"
                         @"Host %@\n"
                         @"\tGSSAPIAuthentication yes\n"
                         @"\tGSSAPIDelegateCredentials yes\n"
                         @"# End of Heracles autoconfigured section", whitelist];
    [fh truncateFileAtOffset:[fh seekToEndOfFile]];
    [fh writeData:[NSMutableData dataWithBytes:[toWrite UTF8String] length:[toWrite length]]];
    [fh closeFile];
    return YES;
}

/*
 * Sets Chrome's MCX settings to enable Kerberos authentication and delegation
 * for the URL `whitelist`.
 */
- (BOOL)whitelistURLForChrome:(NSString *)whitelist {
    NSString *user = NSUserName();
    NSString *prevMCXSettings = [self exec:[NSString stringWithFormat:@"/usr/bin/dscl . -mcxread /Users/%@ com.google.Chrome", user]];
    if (![prevMCXSettings isEqualToString:@""]) NSLog(@"Found previous MCX settings which may be overwritten:\n%@", prevMCXSettings);
    
    /*
     * Use AppleScript to perform operations as administrator since the
     * "proper" Objective-C way to do this (using `SMJobBless`) is not only
     * much more complicated, but also requires a signing certificate, which
     * I currently do not have.
     */
    NSString *scriptSrc = [NSString stringWithFormat:@"do shell script \"/usr/bin/dscl . -mcxset /Users/%@ com.google.Chrome AuthServerWhitelist always '%@' && "
        @"/usr/bin/dscl . -mcxset /Users/%@ com.google.Chrome AuthNegotiateDelegateWhitelist always '%@'\" with administrator privileges", user, whitelist, user, whitelist];
    return [self runScript:scriptSrc];
}

/*
 * Runs `command` and returns its output. The first word of `command` is used
 * as the executable path and each subsequent word is used as an argument. A
 * word is simply a sequence of non-space characters.
 */
- (NSString *)exec:(NSString *)command {
    NSTask *task;
    task = [[NSTask alloc] init];
    
    NSMutableArray *parts = [[command componentsSeparatedByString:@" "] mutableCopy];
    NSString *path = [parts objectAtIndex:0];
    [task setLaunchPath:path];
    
    [parts removeObjectAtIndex:0];
    NSArray *arguments = [parts copy];
    [task setArguments:arguments];
    
    NSPipe *pipe = [NSPipe pipe];
    [task setStandardOutput:pipe];
    NSFileHandle *file = [pipe fileHandleForReading];
    
    DLOG(@"Running command '%@' with arguments '%@'", path, arguments);
    [task launch];
    
    NSData *data = [file readDataToEndOfFile];
    NSString *output = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    if ([output hasSuffix:@"\n"]) output = [output substringToIndex:([output length] - 1)]; // Strip last newline character
    return output;
}

/*
 * Runs an AppleScript with source `source` and returns whether running it was
 * successful.
 */
- (BOOL)runScript:(NSString *)source {
    DLOG(@"Running script with source:\n%@", source);
    NSAppleScript *script = [[NSAppleScript new] initWithSource:source];
    if (script == nil) {
        NSLog(@"Error initalizing script from source:\n%@", source);
        return NO;
    }
    
    NSDictionary *error;
    if ([script executeAndReturnError:&error] == nil) {
        NSLog(@"Error running script with source:\n%@\nError: %@", source, error);
        return NO;
    }
    return YES;
}

/*
 * Brings up an alert asking if the user wants to logout now. If they answer
 * yes, the system logout dialog is brought up.
 */
- (void)alertToLogout {
    NSAlert *alert = [NSAlert alertWithMessageText:@"Do you want to logout now?"
                                     defaultButton:@"Logout"
                                   alternateButton:@"Cancel"
                                       otherButton:nil
                         informativeTextWithFormat:@"You need to logout and log back in to allow Google Chrome's Kerberos settings to take effect. Do you want to logout now?"];
    [[[alert buttons] objectAtIndex:1] setKeyEquivalent:@"\E"];
    if ([alert runModal] == NSAlertDefaultReturn) {
        NSString *scriptSrc = @"tell application \"System Events\" to log out";
        [self runScript:scriptSrc];
    }
}

- (IBAction)leftButtonClicked:(id)sender {
    [rightButton setTitle:@"Continue"];
    [leftButton setHidden:YES];
    [transition setSubtype:kCATransitionFromLeft];
    [[parentView animator] replaceSubview:loginView with:securityWarningView];
}

/*
 * If there is a working internet connection, attempts to authenticate in the
 * background and shows a notification of the result.
 */
- (void)authenticateInBackgroundWithNotification:(NSNotification *)notification {
    if (![reachability isReachable]) return;
    [self authenticateInBackgroundWithTimer:nil];
}

/*
 * Attempts to authenticate in the background and shows a notification of the
 * result.
 */
- (void)authenticateInBackgroundWithTimer:(NSTimer *)timer {
    [self notify:[self authenticateWithUsername:nil withPassword:nil isInBackground:YES]];
}

/*
 * Attempts to authenticate and shows the result using `statusLabel`. Uses the
 * instance variable `username` as the username, and the first argument as
 * the password.
 */
- (void)authenticateInForegroundWithPassword:(NSString *)password {
    NSString *message = [self authenticateWithUsername:nil withPassword:password isInBackground:NO];
    [self setStatus:message error:![self isSuccessfulMessage:message]];
}

/*
 * Attempts to authenticate (i.e. obtain a Kerberos TGT and an AFS token) using
 * the given username and password. If they are nil, the instance variable
 * `username` will be used for the username, and the password will be
 * retrieved from the Keychain. Returns a string representing the outcome of
 * the attempt to authenticate. If `background` is true and Heracles is
 * unable to connect to the internet, the reachability notifier will be
 * started so that it automatically authenticates as soon as a connection is
 * available. 
 */
- (NSString *)authenticateWithUsername:(NSString *)usernameToUse withPassword:(NSString *)passwordToUse isInBackground:(BOOL)background {
    [reachability stopNotifier];
    exitAfterNotify = NO;
    realmName = nil;
    
    NSDictionary *prefs = [[NSUserDefaults standardUserDefaults] persistentDomainForName:@"com.apple.loginwindow"];
    if ([prefs objectForKey:@"autoLoginUser"] != nil) return @"Automatic login is enabled. You can disable it in System Preferences → Security & Privacy → General → Disable automatic login.";
    
    if (usernameToUse == nil) usernameToUse = username;
    if (passwordToUse == nil) {
        passwordToUse = [self getPassword];
        if (passwordToUse == nil) return [NSString stringWithFormat: @"Could not retrieve password for %@.", usernameToUse];
    }
    
    KLPrincipal principal;
    KLStatus status = KLCreatePrincipalFromString([usernameToUse UTF8String], kerberosVersion_V5, &principal);
    if (status != klNoErr) {
        exitAfterNotify = YES;
        KLDisposePrincipal(principal);
        NSLog(@"Error creating principal: %d: %@", status, [self getKerberosErrorMessage:status]);
        return [[NSString alloc] initWithFormat:@"%@ is not a valid Kerberos username.", usernameToUse];
    }
    if (KLDestroyTickets(principal) == klNoErr) NSLog(@"Removed previous Kerberos ticket for %@", usernameToUse);
    
    [self saveRealm:principal];

    status = KLAcquireInitialTicketsWithPassword(principal, NULL, [passwordToUse UTF8String], NULL);
    if (status == klNoErr) {
        @try {
            [self exec:@"/usr/bin/aklog"]; // Obtain AFS tokens
        }
        @catch (NSException * e) {
            NSLog(@"Exception obtaining AFS tokens (you can ignore this if you don't have OpenAFS installed): %@", e);
        }
        
        KLTime expirationTime;
        status = KLTicketExpirationTime(principal, kerberosVersion_V5, &expirationTime);
        
        KLDisposePrincipal(principal);
        if (status == klNoErr) [Timer fireWithTimeIntervalSince1970:expirationTime
                                                             target:self
                                                           selector:@selector(authenticateInBackgroundWithTimer:)];
        else NSLog(@"Error getting expiration time of ticket: %d: %@", status, [self getKerberosErrorMessage:status]);
    } else {
        KLDisposePrincipal(principal);
        return [self checkAcquireTicketsError:status inBackground:background];
    }
    return [[NSString alloc] initWithFormat:@"Successfully obtained Kerberos ticket for %@.", usernameToUse];
}

/*
 * Saves the realm name of `principal` into the instance variable `realm`.
 */
- (void)saveRealm:(KLPrincipal)principal {
    char *instance, *name, *realm;
    // We are only interested in `realm`, but the function crashes if the second and third parameters are NULL
    KLStatus status = KLGetTripletFromPrincipal(principal, &instance, &name, &realm);
    if (status == klNoErr) {
        realmName = @(realm);
        KLDisposeString(instance);
        KLDisposeString(name);
        KLDisposeString(realm);
        DLOG(@"Realm: %@", realmName);
    } else NSLog(@"Error getting realm name: %d: %@", status, [self getKerberosErrorMessage:status]);
}

/*
 * Takes appropriate action based on the error represented by `status`, which
 * should be a value returned by `KLAcquireInitialTicketsWithPassword`.
 */
- (NSString *)checkAcquireTicketsError:(KLStatus)status inBackground:(BOOL)background {
    if (status == KRB5_KDC_UNREACH) {
        if ([reachability isReachable]) return @"Unable to contact the Kerberos server.";
        
        if (background) {
            DLOG(@"Starting reachability notifier.");
            [reachability startNotifier];
        }
        
        return @"Cannot connect to the internet.";
    } else if (status == KRB5KDC_ERR_PREAUTH_FAILED) return @"Incorrect username or password.";
    
    NSString *errorMessage = [self getKerberosErrorMessage:status];
    NSLog(@"Error acquiring tickets: %d: %@", status, errorMessage);
    return [[NSString alloc] initWithFormat:@"Error acquiring tickets: %@.", errorMessage];
}

/*
 * Sets the password in the Keychain for the username `usernameToUse`.
 */
- (OSStatus)setPassword:(NSString *)passwordToUse forUsername:(NSString *)usernameToUse {
    SecKeychainItemRef item;
    OSStatus status = SecKeychainFindGenericPassword(NULL,
                                                     strlen(KEYCHAIN_SERVICE_NAME),
                                                     KEYCHAIN_SERVICE_NAME,
                                                     (int)[usernameToUse length],
                                                     [usernameToUse UTF8String],
                                                     NULL,
                                                     NULL,
                                                     &item);
    if (status == noErr) {
        return SecKeychainItemModifyContent(item, NULL, (UInt32)[passwordToUse length],
                                              [passwordToUse UTF8String]);
    }
    return SecKeychainAddGenericPassword(NULL,
                                         strlen(KEYCHAIN_SERVICE_NAME),
                                         KEYCHAIN_SERVICE_NAME,
                                         (UInt32)[usernameToUse length],
                                         [usernameToUse UTF8String],
                                         (UInt32)[passwordToUse length],
                                         [passwordToUse UTF8String],
                                         NULL);
}

/*
 * Returns the password from the Keychain, or nil if there was an error.
 */
- (NSString *)getPassword {
    UInt32 length;
    void *passwordData = NULL;
    OSStatus status = SecKeychainFindGenericPassword(NULL,
                                                     strlen(KEYCHAIN_SERVICE_NAME),
                                                     KEYCHAIN_SERVICE_NAME,
                                                     (UInt32)[username length],
                                                     [username UTF8String],
                                                     &length,
                                                     &passwordData,
                                                     NULL
                                                     );
    if (status != noErr) {
        exitAfterNotify = YES;
        NSLog(@"Error getting password: %d: %@", status, CFBridgingRelease(SecCopyErrorMessageString(status, NULL)));
        return nil;
    }
    
    NSString *password = [[NSString alloc] initWithBytes:passwordData length:length encoding:NSUTF8StringEncoding];
    SecKeychainItemFreeContent(NULL, passwordData);
    return password;
}

/*
 * Returns a string explaining the error represented by `error`.
 */
- (NSString *)getKerberosErrorMessage:(KLStatus)error {
    char *message;
    KLGetErrorString(error, &message);
    NSString *messageStr = [[NSString alloc] initWithUTF8String:message];
    KLDisposeString(message);
    if ([messageStr hasSuffix:@"\n"]) messageStr = [messageStr substringToIndex:([messageStr length] - 1)]; // Strip last newline
    return messageStr;
}

/*
 * Creates a Growl notification for `message`.
 */
- (void)notify:(NSString *)message {
    NSString *title;
    if ([self isSuccessfulMessage:message]) title = @"Authenticated";
    else title = @"Error Authenticating";
    if (NSClassFromString(@"NSUserNotification") != nil) {
        NSUserNotification *notification = [[NSUserNotification alloc] init];
        [notification setTitle:title];
        [notification setInformativeText:message];
        [[NSUserNotificationCenter defaultUserNotificationCenter] scheduleNotification:notification];
    } else {
        [GrowlApplicationBridge
         notifyWithTitle:title
         description:message
         notificationName:title
         iconData:nil
         priority:0
         isSticky:NO
         clickContext:nil];
    }
    if (exitAfterNotify) exit(1);
}

/*
 * Returns whether `message`, which should be a string returned by
 * `authenticateWithUsername:withPassword:isInBackground:`, represents an
 * error or not.
 */
- (BOOL)isSuccessfulMessage:(NSString *)message {
    return [message hasPrefix:@"Successfully obtained Kerberos ticket for"];
}

@end
