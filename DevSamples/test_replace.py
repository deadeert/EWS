import re
from PyQt5 import QtCore, QtGui, QtWidgets
import ida_kernwin
dock = ida_kernwin.find_widget("Output window")
if dock:
    py_dock = ida_kernwin.PluginForm.FormToPyQtWidget(dock)
    line_edit = py_dock.findChild(QtWidgets.QLineEdit)
    if line_edit:
        try:
            line_edit.removeEventFilter(kpf)
        except:
            pass
        class filter_t(QtCore.QObject):
            def eventFilter(self, obj, event):
                if event.type() == QtCore.QEvent.KeyRelease:
                    self.expand_markers(obj)
                return QtCore.QObject.eventFilter(self, obj, event)
            def expand_markers(self, obj):
                text = obj.text()
                ea = ida_kernwin.get_screen_ea()
                exp_text = re.sub(r"\$!", "0x%x" % ea, text)
                if exp_text != text:
                    obj.setText(exp_text)
        kpf = filter_t()
        line_edit.installEventFilter(kpf)
        print("All set")

