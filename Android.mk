LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
LOCAL_MODULE := inject 
LOCAL_SRC_FILES := inject.c 
LOCAL_LDLIBS += -L$(SYSROOT)/usr/lib -llog
include $(BUILD_EXECUTABLE)


include $(CLEAR_VARS)  
LOCAL_LDLIBS += -L$(SYSROOT)/usr/lib -llog   
LOCAL_MODULE    := hello  
LOCAL_SRC_FILES := hello.c  
include $(BUILD_SHARED_LIBRARY)  