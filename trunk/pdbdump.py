import sys, os
import comtypes
import comtypes.client
import winnt

msdia = comtypes.client.GetModule( r'msdia80.dll' )

from comtypes.gen.Dia2Lib import *

try:
    ds = comtypes.client.CreateObject( msdia.DiaSource )
except:
    os.system('regsvr32 /s msdia80.dll')
    ds = comtypes.client.CreateObject( msdia.DiaSource )


PTRSIZE = 4 # sizeof(void*)/sizeof(char)
LOCATION_STR=('Null', 'Static', 'TLS', 'RegRel', 'ThisRel', 'Enregistered', 'BitField', 'Slot', 'IlRel', 'MetaData', 'Constant')

SymTagNull,         SymTagExe,          SymTagCompiland,    SymTagCompilandDetails, \
SymTagCompilandEnv, SymTagFunction,     SymTagBlock,        SymTagData, \
SymTagAnnotation,   SymTagLabel,        SymTagPublicSymbol, SymTagUDT, \
SymTagEnum,         SymTagFunctionType, SymTagPointerType,  SymTagArrayType, \
SymTagBaseType,     SymTagTypedef,      SymTagBaseClass,    SymTagFriend, \
SymTagFunctionArgType, SymTagFuncDebugStart, SymTagFuncDebugEnd, SymTagUsingNamespace, \
SymTagVTableShape,  SymTagVTable,       SymTagCustom,       SymTagThunk, \
SymTagCustomType,   SymTagManagedType,  SymTagDimension,    SymTagMax = range(32)
SYMTAG_STR  =('Null', 'Exe', 'Compiland', 'CompilandDetails', 'CompilandEnv', 'Function',
              'Block', 'Data', 'Annotation', 'Label', 'PublicSymbol', 'UDT', 'Enum',
              'FunctionType', 'PointerType', 'ArrayType', 'BaseType', 'Typedef',
              'BaseClass', 'Friend', 'FunctionArgType', 'FuncDebugStart', 'FuncDebugEnd',
              'UsingNamespace', 'VTableShape', 'VTable', 'Custom', 'Thunk', 'CustomType',
              'ManagedType', 'Dimension')

DataIsUnknown,      DataIsLocal,        DataIsStaticLocal,  DataIsParam, \
DataIsObjectPtr,    DataIsFileStatic,   DataIsGlobal,       DataIsMember, \
DataIsStaticMember, DataIsConstant = range(10)
DATAKIND_STR=('Unknown', 'Local', 'StaticLocal', 'Param', 'ObjectPtr', 'FileStatic', 'Global', 'Member', 'StaticMember', 'Constant')

UdtStruct, UdtClass, UdtUnion = range(3)
UDTKIND_STR = ('struct', 'class', 'union')

LocIsNull,      LocIsStatic,    LocIsTLS,   LocIsRegRel,    LocIsThisRel,   LocIsEnregistered, \
LocIsBitField,  LocIsSlot,      LocIsIlRel, LocInMetaData,  LocIsConstant,  LocTypeMax = range(12)

btNoType    = 0
btVoid      = 1
btChar      = 2
btWChar     = 3
btInt       = 6
btUInt      = 7
btFloat     = 8
btBCD       = 9
btBool      = 10
btLong      = 13
btULong     = 14
btCurrency  = 25
btDate      = 26
btVariant   = 27
btComplex   = 28
btBit       = 29
btBSTR      = 30
btHresult   = 31


CV_ARM_R0       = 10
CV_ARM_R1       = 11
CV_ARM_R2       = 12
CV_ARM_R3       = 13
CV_ARM_R4       = 14
CV_ARM_R5       = 15
CV_ARM_R6       = 16
CV_ARM_R7       = 17
CV_ARM_R8       = 18
CV_ARM_R9       = 19
CV_ARM_R10      = 20
CV_ARM_R11      = 21 # Frame pointer, if allocated
CV_ARM_R12      = 22
CV_ARM_SP       = 23 # Stack pointer
CV_ARM_LR       = 24 # Link Register
CV_ARM_PC       = 25 # Program counter
CV_ARM_CPSR     = 26 # Current program status register

CV_REG_EAX      =  17
CV_REG_ECX      =  18
CV_REG_EDX      =  19
CV_REG_EBX      =  20
CV_REG_ESP      =  21
CV_REG_EBP      =  22
CV_REG_ESI      =  23
CV_REG_EDI      =  24
CV_REG_EDXEAX   =  212

REGS_ARM={  CV_ARM_R0   :"r0",  CV_ARM_R1   :"r1",  CV_ARM_R2   :"r2",  CV_ARM_R3   :"r3",
            CV_ARM_R4   :"r4",  CV_ARM_R5   :"r5",  CV_ARM_R6   :"r6",  CV_ARM_R7   :"r7",
            CV_ARM_R8   :"r8",  CV_ARM_R9   :"r9",  CV_ARM_R10  :"r10", CV_ARM_R11  :"r11",
            CV_ARM_R12  :"r12", CV_ARM_SP   :"sp",  CV_ARM_LR   :"lr",  CV_ARM_PC   :"pc",
            CV_ARM_CPSR :"cpsr"}
REGS_386={  CV_REG_EAX:  "eax", CV_REG_ECX:  "ecx", CV_REG_EDX:  "edx", CV_REG_EBX:  "ebx",
            CV_REG_ESP:  "esp", CV_REG_EBP:  "ebp", CV_REG_ESI:  "esi", CV_REG_EDI:  "edi",
            CV_REG_EDXEAX: "edx:eax",}
REGS_X64={}
REG_NAMES={ 332:REGS_386, 448:REGS_ARM, 450:REGS_ARM, 512:REGS_X64}


CV_CALL_NEAR_C      = 0x00 #  near right to left push, caller pops stack
CV_CALL_NEAR_FAST   = 0x04 #  near left to right push with regs, callee pops stack
CV_CALL_NEAR_STD    = 0x07 #  near standard call
CV_CALL_NEAR_SYS    = 0x09 #  near sys call
CV_CALL_THISCALL    = 0x0b #  this call (this passed in register)
CALLCONV_STR = {
    CV_CALL_NEAR_C:    "__cdecl",
    CV_CALL_NEAR_FAST: "__fastcall",
    CV_CALL_NEAR_STD:  "__stdcall",
    CV_CALL_NEAR_SYS:  "__syscall",
    CV_CALL_THISCALL:  "__thiscall", }


nsNone = 0
nsfCaseSensitive = 0x1         # apply a case sensitive match
nsfCaseInsensitive = 0x2       # apply a case insensitive match
nsfFNameExt = 0x4              # treat names as paths and apply a filename.ext match
nsfRegularExpression = 0x8     # regular expression
nsfUndecoratedName = 0x10      # applies only to symbols that have both undecorated and decorated names
# predefined names for backward source compatibility
nsCaseSensitive = nsfCaseSensitive             # apply a case sensitive match
nsCaseInsensitive = nsfCaseInsensitive         # apply a case insensitive match
nsFNameExt = nsfCaseInsensitive | nsfFNameExt  # treat names as paths and apply a filename.ext match
nsRegularExpression = nsfRegularExpression | nsfCaseSensitive      # regular expression (using only '*' and '?')
nsCaseInRegularExpression = nsfRegularExpression | nsfCaseInsensitive  # case insensitive regular expression


def findChildren(parent, symTag=SymTagNull, name=None, compareFlags=nsNone):
    for sym in parent.findChildren(symTag, name, compareFlags):
        yield sym.QueryInterface(IDiaSymbol)


def RegisterStr(sym):
    try:
        return REG_NAMES[ses.globalScope.machineType][sym.registerId]
    except:
        return "unkreg_%s_%s" % (sym.machineType, sym.registerId)


def offsetstr(off):
    if off<0:
        return '-%04X' % -off
    return '+%04X' % off

def dumpLocation(sym):
    before = ''
    after = ''
    if sym.locationType==LocIsStatic:           before = "%08X: " % sym.virtualAddress
    elif sym.locationType==LocIsTLS:            before = "tls %04X" % sym.virtualAddress
    elif sym.locationType==LocIsRegRel:         before = "[%s%s]" % (RegisterStr(sym), offsetstr(sym.offset))
    elif sym.locationType==LocIsThisRel:        before = "this%s" % offsetstr(sym.offset)
    elif sym.locationType==LocIsEnregistered:   before = "%s" % RegisterStr(sym)
    elif sym.locationType==LocIsBitField:       before = "bit_%X:%X:%X" % (sym.offset, sym.bitPosition, sym.length)
    elif sym.locationType==LocIsSlot:           before = "slot_%04X" % (sym.slot)
    elif sym.locationType==LocIsIlRel:          before = "ilrel_%04X" % sym.offset
    elif sym.locationType==LocInMetaData:       before = "metatoken_%04X" % sym.token
    elif sym.locationType==LocIsConstant:       pass#before = "value_%s" % sym.value
    elif sym.locationType==LocIsNull:           pass
    else:                                       assert False, LOCATION_STR[sym.locationType]
    return before

def dumpSize(sym):
    return '%4X|' % sym.length


# dump all children which have given tag
def dumpChildrenStr(parent, symTag, dumpbody):
    o = ''
    for sym in findChildren(parent, symTag): #, None, nsfUndecoratedName
        o += dumpSymbol(sym, dumpbody=dumpbody) + ';\n'
    return o

def TAB(text, extra=' '*4, tabpos=22):
    lines = []
    for line in text.split('\n'):
        if len(line)>=tabpos:
            lines.append( line[:tabpos] + extra + line[tabpos:] )
        else:
            lines.append( line )
    newtext = '\n'.join(lines)
    if len(text) and text[-1]=='\n' and (len(newtext)==0 or newtext[-1]!='\n'): newtext+='\n'
    return newtext

def dumpTypeShort(sym, dataname=''):
    def _dumpTypeShort(sym, dataname):
        o = ''
        if sym.symTag==SymTagBaseType:
            bt = sym.baseType
            if bt==btVoid:                            o += 'void'
            elif bt==btChar and sym.length==1:        o += 'char'
            elif bt==btChar:                          o += '__char%d' % (sym.length*8)
            elif bt==btWChar and sym.length==2:       o += 'wchar_t'
            elif bt==btWChar:                         o += '__wchar_t%d' % (sym.length*8)
            elif bt==btInt and sym.length==1:         o += 'signed char'
            elif bt==btInt and sym.length==2:         o += 'short'
            elif bt==btInt and sym.length==4:         o += 'int'
            elif bt==btInt:                           o += '__int%d' % (sym.length*8)
            elif bt==btUInt and sym.length==1:        o += 'unsigned char'
            elif bt==btUInt and sym.length==2:        o += 'unsigned short'
            elif bt==btUInt and sym.length==4:        o += 'unsigned int'
            elif bt==btUInt:                          o += '__uint%d' % (sym.length*8)
            elif bt==btLong and sym.length==PTRSIZE:  o += 'long'
            elif bt==btLong:                          o += '__long%d' % (sym.length*8)
            elif bt==btULong and sym.length==PTRSIZE: o += 'unsigned long'
            elif bt==btULong:                         o += '__ulong%d' % (sym.length*8)
            elif bt==btFloat and sym.length==4:       o += 'float'
            elif bt==btFloat and sym.length==8:       o += 'double'
            elif bt==btFloat:                         o += '__float%d' % (sym.length*8)
            elif bt==btNoType:                        o += '...'
            elif bt==btBCD:                           o += 'BCD'
            elif bt==btBool and sym.length==1:        o += 'bool'
            elif bt==btBool:                          o += '__bool%d' % (sym.length*8)
            elif bt==btCurrency:                      o += 'CURRENCY'
            elif bt==btDate:                          o += 'DATE'
            elif bt==btVariant:                       o += 'VARIANT'
            elif bt==btComplex:                       o += 'COMPLEX'
            elif bt==btBit:                           o += 'BIT'
            elif bt==btBSTR:                          o += 'BSTR'
            elif bt==btHresult:                       o += 'HRESULT'
            else:                                           assert False
            if dataname:
                o += ' \1' + dataname
            else:
                o += '\1'

        elif sym.symTag==SymTagPointerType:
            symbol = '*'
            if sym.reference:
                symbol = '&'
            if sym.length!=PTRSIZE:
                symbol += ' __ptr%d' % (sym.length*8)

            if sym.type.constType:  # pointer to const
                symbol = ' const'+ symbol

            st = _dumpTypeShort(sym.type, dataname)
            o += st .replace('\1','\1'+symbol) .replace('\2','(\1'+symbol) .replace('\3',')')

        elif sym.symTag==SymTagArrayType:
            o += '%s[' % (_dumpTypeShort(sym.type, dataname))
            if not (sym.arrayIndexType.symTag==SymTagBaseType and sym.arrayIndexType.baseType==btULong):
                o += '(%s) ' % dumpTypeShort(sym.arrayIndexType)
            if sym.type.length==0:
                o += '%X/sizeof(%s)] /* ACHTUNG */' % ( sym.length, dumpTypeAndName(sym))
            else:
                o += '%X]' % ( sym.length / sym.type.length)

        elif sym.symTag==SymTagUDT:
            o += '%s %s' % (UDTKIND_STR[sym.UDTKind], sym.name)
            #if sym.nested:
            #    o += '/*nested*/'
            if dataname:
                o += ' \1%s' % dataname
            else:
                o += '\1'

        elif sym.symTag==SymTagEnum:
            o += 'enum %s' % sym.name
            if dataname:
                o += ' %s' % dataname

        elif sym.symTag==SymTagFunctionType:
            o += '%s \2%s' % (dumpTypeShort(sym.type), CALLCONV_STR[sym.callingConvention])
            if dataname:
                o += ' %s' % dataname
            o += '\3'
            oparams = []
            if sym.objectPointerType:
                oparams.append( dumpTypeShort(sym.objectPointerType, 'this') )
            for arg in findChildren(sym, SymTagFunctionArgType):
                oparams.append( dumpTypeShort(arg.type) )
            o += '(' + ', '.join(oparams) + ')'

        else:
            o += '?' + SYMTAG_STR[sym.symTag] + dataname
        return o

    return _dumpTypeShort(sym, dataname) . replace('\1','') . replace('\2','') . replace('\3','')


def dumpTypeAndName(sym):
    return dumpTypeShort(sym.type, sym.name)


# dump whole line(s), "address size ...." but without final ';\n'
def dumpSymbol(sym, dumpbody=False):
    o = ''

    if sym.symTag==SymTagEnum:
        o += '%-12s %-8s ' % ('','')
        o += 'enum %s' % sym.name
        if dumpbody:
            o += '\n'
            o += '%-12s %-8s {\n' % ('','')
            o += TAB( dumpChildrenStr(sym, SymTagData, True) )
            o += '%-12s %-8s }' % ('','')

    elif sym.symTag==SymTagTypedef:
        o += '%-12s %-8s ' % ('',dumpSize(sym.type))
        o += 'typedef %s' % dumpTypeAndName(sym)

    elif sym.symTag==SymTagData:
        o += '%-12s ' % dumpLocation(sym)
        if sym.type:
            o += '%-8s ' % dumpSize(sym.type)
            if sym.dataKind == DataIsConstant:
                assert sym.locationType==LocIsConstant
                o += 'const %s = %s' % (dumpTypeAndName(sym), hex(sym.value))
            elif sym.dataKind in (DataIsFileStatic, DataIsStaticLocal, DataIsStaticMember):
                o += 'static %s' %  (dumpTypeAndName(sym))
            elif sym.dataKind in (DataIsGlobal, DataIsLocal, DataIsMember, DataIsObjectPtr, DataIsParam):
                o += '%s' %  (dumpTypeAndName(sym))
            else:
                o += '%s /* ?%s */' % (dumpTypeAndName(sym), DATAKIND_STR[sym.dataKind])
        else:
            o += '%-8s /*? no type defined */ %s' % ('', sym.name)

    elif sym.symTag==SymTagFunction:
        assert sym.type.symTag == SymTagFunctionType

        if sym.classParent: # if under class
            if sym.type.objectPointerType: # not 'static'
                assert sym.type.objectPointerType.type.name==sym.classParent.name, (sym.type.objectPointerType.type.name, sym.classParent.name)

        #o += '// %s\n' % dumpTypeAndName(sym)
        o += '%-12s %-8s %s %s %s(' % (dumpLocation(sym), dumpSize(sym),
                dumpTypeShort(sym.type.type),
                CALLCONV_STR[sym.callingConvention],
                sym.name)

        oparams = []
        objparam = None # DataIsObjectPtr   child
        params = []     # DataIsParam       children
        for s in findChildren(sym, SymTagData):
            if s.dataKind==DataIsObjectPtr:
                assert objparam==None   # two this
                objparam = s
            elif s.dataKind==DataIsParam:
                params.append(s)
        types = list(findChildren(sym.type, SymTagFunctionArgType))

        assert objparam==None or objparam.name=='this'
        assert objparam==None or ses.symsAreEquiv(objparam.type, sym.type.objectPointerType)

        # no names, print only type information :(
        if len(types)>0 and len(params)==0 and objparam==None:
            if sym.type.objectPointerType:
                oparams.append( '%-12s %-8s %s' % ('','',dumpTypeShort(sym.type.objectPointerType, 'this')) )
            for arg in types:
                oparams.append( '%-12s %-8s %s' % ('','',dumpTypeShort(arg.type)) )
        else:
            if objparam:
                oparams.append( dumpSymbol(objparam) )
            for param in params:
                oparams.append( dumpSymbol(param) )
            for i in xrange(len(params), len(types)):
                # 'scalar deleting destructor' or '...'
                oparams.append('%-12s %-8s %s' % ('','', dumpTypeShort(types[-1].type)))

        if oparams:
            o += '\n' + TAB( ',\n'.join(oparams) )
        o += ')'

        if sym.constType:
            o += ' const'
        #if sym.classParent and sym.pure:
        #    o += ' =0'

        if dumpbody:
            o += '\n%-12s %-8s {\n' % ('','')

            o += TAB( dumpChildrenStr(sym, SymTagTypedef, False) )

            # locals
            olocals = ''
            for s in findChildren(sym, SymTagData):
                assert s.dataKind in (DataIsLocal, DataIsStaticLocal, DataIsParam, DataIsObjectPtr, DataIsConstant), DATAKIND_STR[s.dataKind]
                if s.dataKind in (DataIsLocal, DataIsConstant, DataIsStaticLocal):
                    olocals += dumpSymbol(s)+';\n'
            o += TAB( olocals )


            obodylines = []
            for s in findChildren(sym, SymTagNull): #SymTagFuncDebugStart)
                assert s.symTag in( SymTagFuncDebugStart,
                                    SymTagFuncDebugEnd,
                                    SymTagTypedef,
                                    SymTagData,
                                    SymTagBlock,
                                    SymTagLabel), (SYMTAG_STR[s.symTag])
                if s.symTag==SymTagLabel:
                    obodylines.append('%-12s %-8s %s:' % (dumpLocation(s), '', s.name))
                elif s.symTag==SymTagBlock:
                    obodylines.append('%-12s %-8s %s' % (dumpLocation(s), dumpSize(s), 'Block'))
                elif s.symTag==SymTagFuncDebugStart:
                    obodylines.append('%-12s %-8s %s' % (dumpLocation(s), '', 'DebugStart'))
                elif s.symTag==SymTagFuncDebugEnd:
                    obodylines.append('%-12s %-8s %s' % (dumpLocation(s), '', 'DebugEnd'))

            prevfilename = None
            for line in ses.findLinesByAddr(sym.addressSection, sym.addressOffset, sym.length ):
                line = line.QueryInterface(IDiaLineNumber)
                assert line.lineNumber == line.lineNumberEnd
                assert line.columnNumber == 0
                assert line.columnNumberEnd == 0

                # do not print filename a lot of times
                filename = line.sourceFile.fileName
                if prevfilename == line.sourceFile.fileName:
                    filename = ''
                prevfilename = line.sourceFile.fileName
                obodylines.append('%-12s %-8s # %6d %s' % ( '%08X:'%line.virtualAddress, #relativeVirtualAddress,
                    '', line.lineNumber, filename)) #, line.compiland.name
            o += TAB('\n'.join(sorted(obodylines))) + '\n'

            o += '%-12s %-8s }' % ('','')

    elif sym.symTag==SymTagBaseClass:
        o += '%-12s %-8s ' % (dumpLocation(sym), dumpSize(sym))
        #o = '%-12s %-8s ' % ('base+%04X' % sym.offset, dumpSize(sym))
        if sym.virtual: o += 'virtual '
        if sym.indirectVirtualBaseClass: o += 'indirect '
        o += '%s %s' % (UDTKIND_STR[sym.udtKind], sym.name)
        if sym.virtual:
            o += '/*<vbase pointer offset %04X>*/' % sym.virtualBasePointerOffset
            o += '/*<vbase displacement index %04X>*/' % sym.virtualBaseDispIndex

    elif sym.symTag==SymTagUDT:
        o += '%-12s %-8s %s %s' % ('', dumpSize(sym), UDTKIND_STR[sym.udtKind], sym.name)

        if dumpbody:

            obase = ',\n'.join(dumpSymbol(s) for s in findChildren(sym, SymTagBaseClass))
            if obase:
                o += ' :\n' + TAB(obase)
            o += '\n'

            o += '%-12s %-8s {\n' % ('','')

            #o += '// typedefs\n'
            o += TAB( dumpChildrenStr(sym, SymTagTypedef, False) )
            #o += '// enums\n'
            o += TAB( dumpChildrenStr(sym, SymTagEnum, False) )
            #o += '// datas\n'
            o += TAB( dumpChildrenStr(sym, SymTagData, False) )

            #o += '// functions\n'
            for symfunc in findChildren(sym, SymTagFunction):
                ofunc = dumpSymbol(symfunc, dumpbody=False)
                if symfunc.virtual:
                    ofunc = ofunc[:22] + 'virtual ' + ofunc[22:] + (' /*vtbl+%04X*/' % sym.virtualBaseOffset)
                elif not symfunc.type.objectPointerType:
                    ofunc = ofunc[:22] + 'static ' + ofunc[22:]
                o += TAB(ofunc) + ';\n'

            o += '%-12s %-8s }' % ('','')

    elif sym.symTag==SymTagPublicSymbol:
        o += '%-12s %-8s ' % (dumpLocation(sym), dumpSize(sym))
        o += sym.undecoratedName
        o += ' '
        o += sym.name
    else:
        o += '?ACHTUNG '+SYMTAG_STR[sym.symTag]
    return o

if __name__=='__main__':

    try:
        arg = sys.argv[1]
    except:
        arg = 'vc80.pdb'

    try:
        ds.loadDataFromPdb(arg)
    except:
        ds.loadDataForExe(arg, '', None)

    ses = ds.openSession()

    #ses.loadAddress = 0x00400000

    # DUMP GLOBALS
    #print '\n/* Globals */\n', dumpChildrenStr(ses.globalScope, SymTagData, dumpbody=True)
    for sym in findChildren(ses.globalScope, SymTagData):
        print dumpSymbol(sym, dumpbody=True) + ';'

    # DUMP ALL ENUMS
    #print '\n/* Enums */\n', dumpChildrenStr(ses.globalScope, SymTagEnum, dumpbody=True)
    for sym in findChildren(ses.globalScope, SymTagEnum):
        print dumpSymbol(sym, dumpbody=True) + ';'

    # DUMP ALL TYPEDEFS
    #print '\n/* Typedefs */\n', dumpChildrenStr(ses.globalScope, SymTagTypedef, dumpbody=True)
    for sym in findChildren(ses.globalScope, SymTagTypedef):
        print dumpSymbol(sym, dumpbody=True) + ';'

    # DUMP ALL FUNCTIONS
    #print '\n/* Functions */\n', dumpChildrenStr(ses.globalScope, SymTagFunction, dumpbody=True)
    for sym in findChildren(ses.globalScope, SymTagFunction):
        print dumpSymbol(sym, dumpbody=True) + ';'

    # DUMP ALL UDT
    #print '\n/* UDT */\n', dumpChildrenStr(ses.globalScope, SymTagUDT, dumpbody=True)
    for sym in findChildren(ses.globalScope, SymTagUDT):
        print dumpSymbol(sym, dumpbody=True) + ';'

    # DUMP ALL PUBLICS
    #print '\n/* Public Symbols */\n', dumpChildrenStr(ses.globalScope, SymTagPublicSymbol, dumpbody=True)
    for sym in findChildren(ses.globalScope, SymTagPublicSymbol):
        print dumpSymbol(sym, dumpbody=True) + ';'
