/*++
Copyright (c) 2011 Microsoft Corporation

Module Name:

    scoped_ctrl_c.h

Abstract:

    Scoped control-c handler.

Author:

    Leonardo de Moura (leonardo) 2011-04-27.

Revision History:

--*/
#pragma once

#include "util/event_handler.h"
#include "util/util.h"

void signal_lock(void);
void signal_unlock(void);

struct scoped_ctrl_c {
    event_handler & m_cancel_eh;
    bool m_first;
    bool m_once;
    bool m_enabled;
public:
    // If once == true, then the cancel_eh is invoked only at the first Ctrl-C.
    // The next time, the old signal handler will take over.
    // if enabled == false, then scoped_ctrl_c is a noop
    scoped_ctrl_c(event_handler & eh, bool once=true, bool enabled=true);
    ~scoped_ctrl_c();
    void reset() { m_first = true; }
};

