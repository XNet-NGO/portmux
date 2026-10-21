/*
 ============================================================================
 Name        : portmux-log.h
 Description : Minimal leveled logger.
 ============================================================================
 */

#ifndef __PORTMUX_LOG_H__
#define __PORTMUX_LOG_H__

#include <stdio.h>

/* 0=off 1=error 2=warn 3=info 4=debug */
extern int portmux_log_level;

#define PM_LOG(lvl, tag, fmt, ...)                                      \
    do {                                                                \
        if (portmux_log_level >= (lvl))                                 \
            fprintf (stderr, "[portmux] " tag " " fmt "\n", ##__VA_ARGS__); \
    } while (0)

#define PM_LOG_E(fmt, ...) PM_LOG (1, "E", fmt, ##__VA_ARGS__)
#define PM_LOG_W(fmt, ...) PM_LOG (2, "W", fmt, ##__VA_ARGS__)
#define PM_LOG_I(fmt, ...) PM_LOG (3, "I", fmt, ##__VA_ARGS__)
#define PM_LOG_D(fmt, ...) PM_LOG (4, "D", fmt, ##__VA_ARGS__)

#endif /* __PORTMUX_LOG_H__ */
