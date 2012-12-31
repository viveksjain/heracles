//
//  Copyright (c) 2012 Vivek Jain. All rights reserved.
//

#import "Timer.h"

static NSTimer *timer;
static NSDate *fireDate;

@implementation Timer

+ (void)initialize {
    [[[NSWorkspace sharedWorkspace] notificationCenter] addObserver:self selector:@selector(resetTimer:) name:NSWorkspaceDidWakeNotification object:nil];
}

+ (void)resetTimer:(NSNotification *)notification {
    if (timer != nil) {
        if (fireDate != nil) {
            DLOG(@"Resetting timer to %@", fireDate);
            [timer setFireDate:fireDate];
        } else NSLog(@"Timer found, but fireDate not found.");
    }
}

+ (void)fireWithTimeIntervalSince1970:(NSTimeInterval)seconds target:(id)target selector:(SEL)selector {
    fireDate = [NSDate dateWithTimeIntervalSince1970:seconds];
    DLOG(@"Next fire date: %@", fireDate);
    if (timer != nil) [timer invalidate];
    timer = [NSTimer scheduledTimerWithTimeInterval:[fireDate timeIntervalSinceNow] target:target selector:selector userInfo:nil repeats:NO];
}

@end
