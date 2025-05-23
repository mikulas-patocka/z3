/*++
Copyright (c) 2011 Microsoft Corporation

Module Name:

    cancel_eh.h

Abstract:

    Template for implementing simple event handler that just invokes cancel method.

Author:

    Leonardo de Moura (leonardo) 2011-04-27.

Revision History:

--*/
#pragma once

#include <atomic>
#include "util/event_handler.h"
#include "util/scoped_ctrl_c.h"

/**
   \brief Generic event handler for invoking cancel method.
*/
template<typename T>
class cancel_eh : public event_handler {
    std::atomic<bool> m_canceled = false;
    bool m_auto_cancel = false;
    T & m_obj;
public:
    cancel_eh(T & o): m_obj(o) {}
    ~cancel_eh() override { if (m_canceled) m_obj.dec_cancel(); if (m_auto_cancel) m_obj.auto_cancel(); }
    void operator()(event_handler_caller_t caller_id) override {
        signal_lock();
        if (!m_canceled) {
            m_caller_id = caller_id;
            m_canceled = true;
            m_obj.inc_cancel(); 
        }
        signal_unlock();
    }
    bool canceled() {
        bool ret;
        if (!m_canceled)
            return false;
        signal_lock();
        ret = m_canceled;
        signal_unlock();
        return ret;
    }
    void reset() {
        signal_lock();
        m_canceled = false;
        signal_unlock();
    }
    T& t() { return m_obj; }
    void set_auto_cancel() { m_auto_cancel = true; }
};

