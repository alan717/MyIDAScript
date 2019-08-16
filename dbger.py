# coding=utf-8
from idaapi import * 
class DbgHook(DBG_Hooks):
	bpList={}
	def __init__(self):
		DBG_Hooks.__init__(self)
		self.function_libc_kill = LocByName("kill")
		self.bpList['kill']=self.function_libc_kill
		if self.function_libc_kill != BADADDR:
			print "kill break"
			AddBpt(self.function_libc_kill)
		
	def dbg_process_start(self, pid, tid, ea, name, base, size):
		print("MyDbgHook : Process started, pid=%d tid=%d name=%s" % (pid, tid, name))  
		return
		
	def dbg_process_exit(self, pid, tid, ea, code):
		return
		
	def dbg_library_load(self, pid, tid, ea, name, base, size):
		print "loadlibrary:%s 0x%x"%(name,base)
		return
		
	def dbg_bpt(self, tid,ea):
		print "=========================================="
		print "Break point at 0x%x pid=%d" % (ea, tid)
		print hex(ea),idc.GetDisasm(ea)
		print "r1: 0x%x,0x%x,0x%x,0x%x," % (idc.GetRegValue('R1'),idc.GetRegValue('R2'),idc.GetRegValue('R3'),idc.GetRegValue('R4'))
		for name, adr in self.bpList.iteritems():
			if adr == ea:
				#print "function:%s,data" % name
				if name=="jiami_out":
					#print "jiami_out:%s" % self.get_hex(idc.GetRegValue('R2'),129)
					print "3.加密结束oFUCK U 加密结束oFUCK U 加密结束oFUCK U 加密结束oFUCK U 加密结束oFUCK U 加密结束oFUCK U "
				if name=="jiami_in":
					print "2.jiami_in:%s" % self.get_string(idc.GetRegValue('R2'))
				if name=="base64":
					print "4.base64:%s" %self.get_hex(idc.GetRegValue('R1'),129)
				if name=="first_":
					#print "data:%s"% self.get_string(idc.GetRegValue('R1'),129)
					print "1.first_challenge:%x,%x,%x,%x,%x"%(idc.GetRegValue('R2'),idc.GetRegValue('R3'),idc.GetRegValue('R4'),idc.GetRegValue('R5'),idc.GetRegValue('R6'))
				if name=="sw_0":
					print "sw_0.jiami_in:%s" % self.get_string(idc.GetRegValue('R2'))
				if name=="sw_1":
					print "sw_1.jiami_in:%s" % self.get_string(idc.GetRegValue('R2'))
						
			
		return 0
		
	def dbg_suspend_process(self):
		print "Process suspended"
		# 这句话让继续运行，相当于gdb的conti
		idaapi.continue_process()
		
	def dbg_trace(self, tid, ea):
		print("Trace tid=%d ea=0x%x" % (tid, ea))
		# return values:
		#   1  - do not log this trace event;
		#   0  - log it
		return 0
		
	def dbg_run_to(self, pid, tid=0, ea=0):
		print "Runto: tid=%d" % tid
		idaapi.continue_process()

	#添加断点
	def add_breakpointer(self):
		print '[*]Find linker begin...'
		libname = 'libjdbitmapkit.so'
		linker = 'linker'
		#JNI_OnLoad 下断点
		module_base = self.get_module_base(libname)
		if module_base != None:
			module_size = idc.GetModuleSize(module_base)
			print '[*] %s base=>0x%08X, Size=0x%08X' % (libname,module_base, module_size)
			offset=0x000114E0  #######加密函数点first_challenge->switch:sub_114E0开始
			addr = module_base + offset
			print "bp : %08X,%08X"% (addr,offset)
			idc.AddBpt(addr)
			self.bpList['jiami_in']=addr
			offset=0x00012D2E  #######加密函数点first_challenge->switch:sub_114E0开始
			addr = module_base + offset
			print "bp : %08X,%08X"% (addr,offset)
			idc.AddBpt(addr)
			func_name=idc.GetFunctionName(addr)
			print "func_name:%s" %func_name
			self.bpList["jiami_out"]=addr
			offset=0x0001316E #0001316E
			addr = module_base + offset
			print "bp : %08X,%08X"% (addr,offset)
			idc.AddBpt(addr)
			self.bpList["base64"]=addr
			offset=0x00013134
			addr = module_base + offset
			print "bp : %08X,%08X"% (addr,offset)
			idc.AddBpt(addr)
			self.bpList["first_"]=addr
			offset=0x00012D3C
			addr = module_base + offset
			print "bp : %08X,%08X"% (addr,offset)
			idc.AddBpt(addr)
			self.bpList["sw_1"]=addr
			offset=0x00012CCC
			addr = module_base + offset
			print "bp : %08X,%08X"% (addr,offset)
			idc.AddBpt(addr)
			self.bpList["sw_0"]=addr
			
	#获取模块基地址
	def get_module_base(self,moduleName):
		print "get_module_base: %s" % moduleName
		module_base = idc.GetFirstModule()
		while module_base != None:
			module_name = idc.GetModuleName(module_base)
			if module_name.find(moduleName) >= 0:
				print module_name
				break
			module_base = idc.GetNextModule(module_base)
		return  module_base
	
	def get_string(self,addr):
		iout=""
		while True:
			if idc.Byte(addr)!=0:
				iout+=chr(Byte(addr))
			else:
				break
			addr+=1
		return iout
		
	def get_hex(self,addr,lens):
		out=""
		while lens > 0:
			out+=hex(idc.get_wide_byte(addr))
			#print "addr:%d,addr:%x,data:%s"%(lens,addr,hex(idc.get_wide_byte(addr)))
			lens-=1
			addr+=1
		return out



debugger = DbgHook()
debugger.hook()
debugger.add_breakpointer()
