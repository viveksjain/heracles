//
//  Copyright (c) 2012 Vivek Jain. All rights reserved.
//
//  This class is a simple wrapper for NSTimer, with the additional properties
//  that only one timer can be running at time, and the timer takes into account
//  the time spent sleeping (whereas NSTimer considers any sleep time as 0
//  seconds having elapsed).
//

#import <Foundation/Foundation.h>

@interface Timer : NSObject

+ (void)fireWithTimeIntervalSince1970:(NSTimeInterval)seconds target:(id)target selector:(SEL)selector;

@end
