"""Windows service host (LocalSystem, automatic delayed start, restart on failure)."""
import threading

import servicemanager
import win32event
import win32service
import win32serviceutil

from common import PRODUCT, SERVICE_NAME, log, setup_logging


class AgentService(win32serviceutil.ServiceFramework):
    _svc_name_ = SERVICE_NAME
    _svc_display_name_ = PRODUCT
    _svc_description_ = "Collects hardware and software inventory and reports it to the IT asset portal over an encrypted channel."

    def __init__(self, args):
        super().__init__(args)
        self.stop_event = threading.Event()

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        self.stop_event.set()

    def SvcDoRun(self):
        setup_logging("agent")
        servicemanager.LogMsg(servicemanager.EVENTLOG_INFORMATION_TYPE, servicemanager.PYS_SERVICE_STARTED, (self._svc_name_, ""))
        try:
            from runtime import run_loop
            run_loop(self.stop_event)
        except Exception:
            log.exception("Service crashed")
            raise


def dispatch():
    servicemanager.Initialize()
    servicemanager.PrepareToHostSingle(AgentService)
    servicemanager.StartServiceCtrlDispatcher()
    return 0


def service_state():
    """'running', 'stopped', ... or None when the service is not installed."""
    try:
        state = win32serviceutil.QueryServiceStatus(SERVICE_NAME)[1]
    except Exception:
        return None
    return {win32service.SERVICE_RUNNING: "running", win32service.SERVICE_STOPPED: "stopped",
            win32service.SERVICE_START_PENDING: "starting", win32service.SERVICE_STOP_PENDING: "stopping"}.get(state, "unknown")
