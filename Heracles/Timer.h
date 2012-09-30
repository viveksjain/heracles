//
//  Copyright (c) 2012 Vivek Jain. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface Timer : NSObject

+ (void)fireWithTimeIntervalSince1970:(NSTimeInterval)seconds target:(id)target selector:(SEL)selector;

@end
