/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef SINGLETON_H
#define SINGLETON_H


#define SINGLETON_DEFINE(CLASS) \
    public: \
    static CLASS *instance(); \
    private: \
    static CLASS *singleton_;                   \

#define SINGLETON_IMPL(CLASS) \
    CLASS* CLASS::singleton_; \
    CLASS* CLASS::instance() { \
        if (singleton_ == NULL) { \
            static CLASS instance; \
            singleton_ = &instance; \
        } \
        return singleton_; \
    }

#endif // SINGLETON_H
