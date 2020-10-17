# coding: utf-8
import idautils
import idaapi
import idc
import re
from sets import Set

class RegexCore:
    FIND_CLASS_NAME_RE = r'([A-Za-z0-9_]{1,256})'
    FIND_METHOD_NAME_RE = r'::([A-Za-z0-9_]{1,256})\('
    FIND_METHOD_ARGS_RE = r'\(([A-Za-z0-9_\s\,&*]{1,256})\)'
    FIND_DESTRUCTOR_METHOD_RE = r'::\~([A-Za-z0-9_]{1,256})\(\)'
    FIND_CXX_GENERIC_TYPES_RE = r'(bool|char|uchar|unsigned char|byte|BYTE|uint8_t|int8_t|uint8|int8|short|ushort|unsigned short|int16_t|int16|uint16_t|uint16|int|uint|unsigned int|unsigned|signed|uint32_t|uint32|int32_t|int32|long long|unsigned long long|int64_t|int64|uint64_t|uint64|double|float|const|\*|\&|std\:\:[a-z0-9\<\>]{1,128})'

class CXXTypeKind:
    CXX_ENUM            = 0x01
    CXX_CLASS_OR_STRUCT = 0x02

class CXXClassUtils:
    @staticmethod
    def GetClassName(entity):
        rawName, addr, rawAddr = entity
        result = re.search(RegexCore.FIND_CLASS_NAME_RE, rawName)
        if result:
            return result.group(0)
        else:
            return None

    @staticmethod
    def GetMemberName(rawName):
        result = re.search(RegexCore.FIND_METHOD_NAME_RE, rawName)
        if result:
            return result.group(0).replace(':', '').replace('(', '').replace(')', '');
        else:
            return None

    @staticmethod
    def GetMemberArgs(rawName):
        result = re.search(RegexCore.FIND_METHOD_ARGS_RE, rawName)
        if result:
            dirtyName = result.group(0)
            # Remove (void) template
            return re.sub(r'\(void\)', '()', dirtyName)
        else:
            return None

    @staticmethod
    def GetDestructorName(rawName):
        result = re.search(RegexCore.FIND_DESTRUCTOR_METHOD_RE, rawName)
        if result:
            dirtyName = result.group(0)
            # Remove ::~ template
            return dirtyName.replace('::~', 'Release_').replace('()', '')
        else:
            return None
    
    @staticmethod
    def GetMemberNameWithArgsList(rawName):
        memberName = CXXClassUtils.GetMemberName(rawName)
        isDestructor = False
        if not memberName:
            destructorName = CXXClassUtils.GetDestructorName(rawName)
            if not destructorName:
                return None
            else:
                memberName = destructorName
                isDestructor = True
        
        memberArgs = CXXClassUtils.GetMemberArgs(rawName)
        if not memberArgs:
            if isDestructor:
                memberArgs = "()"
            else:
                return None

        return "virtual void {}{};".format(memberName, memberArgs)

    @staticmethod
    def IsEnum(rawName):
        """
            In most cases enum type name starts from E (most cases) or from e
        """
        return rawName[0] == 'E' or rawName[0] == 'e'

    @staticmethod
    def IsClassOrStruct(rawName):
        return not CXXClassUtils.IsEnum(rawName) and (rawName[0] == 'Z' or rawName[0] == 'C' or rawName[0] == 'S')

    @staticmethod
    def GetAllTypeReferencesFromFunctionDeclaration(rawName):
        argsStr = CXXClassUtils.GetMemberArgs(rawName)
        if not argsStr:
            return None

        argsStr = re.sub(r'(\*|\&|\s|const|\.\.\.|\(|\))', "", argsStr)
        argsStr = re.sub(RegexCore.FIND_CXX_GENERIC_TYPES_RE, "", argsStr)
        args = argsStr.split(',')

        refs = set()
        for arg in args:
            if len(arg) == 0:
                continue
            refs.add(arg)

        return refs

    @staticmethod
    def GenerateTypeForwardings(entities):
        result = set()

        for funcName, _funcAddr, _vftableAddr in entities:
            typeRefsSet = CXXClassUtils.GetAllTypeReferencesFromFunctionDeclaration(funcName)
            if not typeRefsSet:
                continue

            for typeReference in typeRefsSet:
                if CXXClassUtils.IsEnum(typeReference):
                    result.add("enum class {};".format(typeReference))
                elif CXXClassUtils.IsClassOrStruct(typeReference):
                    result.add("class {};".format(typeReference))
        
        return result

class Limits:
    MAX_FUNCTIONS_PER_VFTABLE = 1024

class GenerateClassRepresentationAction(idaapi.action_handler_t):
    GN_DEMANGLED = 0x0004

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, context):
        # Read current selection
        is_selected, select_begin, select_end = idaapi.read_selection()
        if not is_selected:
            select_begin = ScreenEA()
        
        print("Selection from {:08X}".format(select_begin))

        functionsList = list()
        hasLimitOut = False
        hasAnyFunctions = True
        byteAddr = select_begin

        while hasAnyFunctions and not hasLimitOut:
            bytes = bytearray(idc.get_bytes(byteAddr, 4))
            addr = int(''.join('{:02X}'.format(x) for x in bytes[::-1]), 16)
            # Get info about func
            func = idaapi.get_func(addr)
            if not func:
                hasAnyFunctions = False
                print("End of vftable. Total entities: {}".format(len(functionsList)))
                break

            funcName = idc.get_name(addr, GN_DEMANGLED)
            functionsList.append((funcName, addr, byteAddr))
            byteAddr = byteAddr + 4 # Jump to next addr
            hasLimitOut = len(functionsList) >= Limits.MAX_FUNCTIONS_PER_VFTABLE
        
        # Generate CXX class by vftable
        if len(functionsList) == 0:
            print("Unable to locate first method of class at {:08X}".format(select_begin))
            return 1
        
        className = CXXClassUtils.GetClassName(functionsList[0])
        if not className:
            print("Unable to parse class at {:08X}".format(select_begin))
            return 1

        src = "// Type forwardings for class {}\n".format(className)
        typeForwardings = CXXClassUtils.GenerateTypeForwardings(functionsList[1:])
        for typeForward in typeForwardings:
            src = src + "{}\n".format(typeForward)
        
        src = src + "// Class definition {}\n".format(className)
        src = src + "class {} {{\n".format(className)
        # Generate vftable members
        vftblIndex = 0
        for rawName, funcAddr, _rawAddr in functionsList[1:]:
            src = src + "\t{} //#{:04} at {:08X} org {}\n".format(
                    CXXClassUtils.GetMemberNameWithArgsList(rawName), 
                    vftblIndex, 
                    funcAddr, 
                    rawName
                )
            vftblIndex = vftblIndex + 1
        # Finalize class
        src += "}}; //End of {} from {:08X}".format(className, select_begin)
        print("Class source: \n\n{}".format(src))
        
        # End of plugin
        return 1

    def update(self, context):
        return idaapi.AST_ENABLE_ALWAYS

def main():
    # Unregister previous action
    idaapi.detach_action_from_menu('Edit/Other/', 'DronCode:GenerateClassRepresentationCxxAction')
    idaapi.unregister_action('DronCode:GenerateClassRepresentationCxxAction')

    # Register our action
    action_description = idaapi.action_desc_t(
        'DronCode:GenerateClassRepresentationCxxAction',
        'Generate C/C++ Class Defs',
        GenerateClassRepresentationAction()
    )

    idaapi.register_action(action_description)
    idaapi.attach_action_to_menu('Edit/Other/Toggle border', 'DronCode:GenerateClassRepresentationCxxAction', idaapi.SETMENU_APP)
    print("Plugin registered!")
    
if __name__ == "__main__":
    main()