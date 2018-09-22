import frida

from angrdbg import *


class RemoteFile(object):
    def __init__(self, dbg, name, base):
        self.dbg = dbg
        self.name = name
        self.base = base
        self.pos = 0
    
    def __eq__(self, o):
        try:
            return self.name == o.name
        except:
            return False
    
    def read(self, size):
        v = self.dbg.get_bytes(self.base + self.pos, size)
        self.pos += size
        return v
    
    def seek(self, pos):
        p = self.pos
        self.pos = pos
        return pos


class FridaDebugger(Debugger):
    name = "frida"
    
    def __init__(self, session, api):
        self.session = session
        self.api = api
        
        self.get_byte = api.get_byte
        self.get_word = api.get_word
        self.get_dword = api.get_dword
        self.get_qword = api.get_qword
        self.get_bytes = api.get_bytes
    
    # -------------------------------------
    def before_stateshot(self):
        pass

    def after_stateshot(self, state):
        pass

    # -------------------------------------
    def is_active(self):
        raise NotImplementedError()

    # -------------------------------------
    def input_file(self):  # the file will be closed after a read
        return RemoteFile(self, "_aot_", self.api.get_aot_module_addr())

    def image_base(self):
        return self.api.get_aot_module_addr()

    # -------------------------------------

    def put_byte(self, addr, value):
        raise NotImplementedError()

    def put_word(self, addr, value):
        raise NotImplementedError()

    def put_dword(self, addr, value):
        raise NotImplementedError()

    def put_qword(self, addr, value):
        raise NotImplementedError()

    def put_bytes(self, addr, value):
        raise NotImplementedError()

    # -------------------------------------
    def get_reg(self, name):
        raise NotImplementedError()

    def set_reg(self, name, value):
        raise NotImplementedError()

    # -------------------------------------
    def step_into(self):
        raise NotImplementedError()

    def run(self):
        raise NotImplementedError()

    def wait_ready(self):
        raise NotImplementedError()

    def refresh_memory(self):
        raise NotImplementedError()

    # -------------------------------------
    def seg_by_name(self, name):
        raise NotImplementedError()

    def seg_by_addr(self, name):
        raise NotImplementedError()

    def get_got(self):  # return tuple(start_addr, end_addr)
        raise NotImplementedError()

    def get_plt(self):  # return tuple(start_addr, end_addr)
        raise NotImplementedError()

    # -------------------------------------
    def resolve_name(self, addr):  # return None on fail
        raise NotImplementedError()



def init(session):
    with open("fridangr.js") as code:
        script = session.create_script(code.read())

    script.load()
    api = script.exports

    register_debugger(FridaDebugger(session, api))


def test():
    session = frida.attach("test")
    init(session)

if __name__ == "__main__":
    test()


