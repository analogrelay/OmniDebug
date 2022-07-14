// ReSharper disable All
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace OmniDebug.Interop;

unsafe record struct MetaDataImportPtr(IntPtr Pointer)
{
    public MetaDataImport? DerefOrDefault() => MetaDataImport.Create(this);
    public MetaDataImport Deref() => MetaDataImport.Create(this) ?? throw new InvalidOperationException("Pointer was null");
}

unsafe class MetaDataImport: CallableCOMWrapper
{
    ref readonly IMetaDataImportVTable VTable => ref Unsafe.AsRef<IMetaDataImportVTable>(_vtable);
    public static MetaDataImport? Create(IntPtr punk) => punk != IntPtr.Zero ? new MetaDataImport(punk) : null;
    public static MetaDataImport? Create(MetaDataImportPtr p) => Create(p.Pointer);
    MetaDataImport(IntPtr punk): base(new RefCountedFreeLibrary(IntPtr.Zero), InterfaceIds.IMetaDataImport, punk)
    {
        SuppressRelease();
    }

    public void CloseEnum(IntPtr hEnum)
        => VTable.CloseEnumPtr(Self, hEnum);

    public HResult CountEnum(IntPtr hEnum, ref uint pulCount)
        => VTable.CountEnumPtr(Self, hEnum, ref pulCount);

    public HResult ResetEnum(IntPtr hEnum, uint ulPos)
        => VTable.ResetEnumPtr(Self, hEnum, ulPos);

    public HResult EnumTypeDefs(ref IntPtr phEnum, uint[] rTypeDefs, uint cMax, ref uint pcTypeDefs)
        => VTable.EnumTypeDefsPtr(Self, ref phEnum, rTypeDefs, cMax, ref pcTypeDefs);

    public HResult EnumInterfaceImpls(ref IntPtr phEnum, uint td, uint[] rImpls, uint cMax, ref uint pcImpls)
        => VTable.EnumInterfaceImplsPtr(Self, ref phEnum, td, rImpls, cMax, ref pcImpls);

    public HResult EnumTypeRefs(ref IntPtr phEnum, uint[] rTypeRefs, uint cMax, ref uint pcTypeRefs)
        => VTable.EnumTypeRefsPtr(Self, ref phEnum, rTypeRefs, cMax, ref pcTypeRefs);

    public HResult FindTypeDefByName(ref ushort szTypeDef, uint tkEnclosingClass, ref uint ptd)
        => VTable.FindTypeDefByNamePtr(Self, ref szTypeDef, tkEnclosingClass, ref ptd);

    public HResult GetScopeProps(char* szName, uint cchName, ref uint pchName, ref Guid pmvid)
        => VTable.GetScopePropsPtr(Self, szName, cchName, ref pchName, ref pmvid);

    public HResult GetModuleFromScope(ref uint pmd)
        => VTable.GetModuleFromScopePtr(Self, ref pmd);

    public HResult GetTypeDefProps(uint td, char* szTypeDef, uint cchTypeDef, ref uint pchTypeDef, ref uint pdwTypeDefFlags, ref uint ptkExtends)
        => VTable.GetTypeDefPropsPtr(Self, td, szTypeDef, cchTypeDef, ref pchTypeDef, ref pdwTypeDefFlags, ref ptkExtends);

    public HResult GetInterfaceImplProps(uint iiImpl, ref uint pClass, ref uint ptkIface)
        => VTable.GetInterfaceImplPropsPtr(Self, iiImpl, ref pClass, ref ptkIface);

    public HResult GetTypeRefProps(uint tr, ref uint ptkResolutionScope, char* szName, uint cchName, ref uint pchName)
        => VTable.GetTypeRefPropsPtr(Self, tr, ref ptkResolutionScope, szName, cchName, ref pchName);

    public HResult ResolveTypeRef(uint tr, ref Guid riid, ref IntPtr ppIScope, ref uint ptd)
        => VTable.ResolveTypeRefPtr(Self, tr, ref riid, ref ppIScope, ref ptd);

    public HResult EnumMembers(ref IntPtr phEnum, uint cl, uint[] rMembers, uint cMax, ref uint pcTokens)
        => VTable.EnumMembersPtr(Self, ref phEnum, cl, rMembers, cMax, ref pcTokens);

    public HResult EnumMembersWithName(ref IntPtr phEnum, uint cl, ref ushort szName, uint[] rMembers, uint cMax, ref uint pcTokens)
        => VTable.EnumMembersWithNamePtr(Self, ref phEnum, cl, ref szName, rMembers, cMax, ref pcTokens);

    public HResult EnumMethods(ref IntPtr phEnum, uint cl, uint[] rMethods, uint cMax, ref uint pcTokens)
        => VTable.EnumMethodsPtr(Self, ref phEnum, cl, rMethods, cMax, ref pcTokens);

    public HResult EnumMethodsWithName(ref IntPtr phEnum, uint cl, ref ushort szName, uint[] rMethods, uint cMax, ref uint pcTokens)
        => VTable.EnumMethodsWithNamePtr(Self, ref phEnum, cl, ref szName, rMethods, cMax, ref pcTokens);

    public HResult EnumFields(ref IntPtr phEnum, uint cl, uint[] rFields, uint cMax, ref uint pcTokens)
        => VTable.EnumFieldsPtr(Self, ref phEnum, cl, rFields, cMax, ref pcTokens);

    public HResult EnumFieldsWithName(ref IntPtr phEnum, uint cl, ref ushort szName, uint[] rFields, uint cMax, ref uint pcTokens)
        => VTable.EnumFieldsWithNamePtr(Self, ref phEnum, cl, ref szName, rFields, cMax, ref pcTokens);

    public HResult EnumParams(ref IntPtr phEnum, uint mb, uint[] rParams, uint cMax, ref uint pcTokens)
        => VTable.EnumParamsPtr(Self, ref phEnum, mb, rParams, cMax, ref pcTokens);

    public HResult EnumMemberRefs(ref IntPtr phEnum, uint tkParent, uint[] rMemberRefs, uint cMax, ref uint pcTokens)
        => VTable.EnumMemberRefsPtr(Self, ref phEnum, tkParent, rMemberRefs, cMax, ref pcTokens);

    public HResult EnumMethodImpls(ref IntPtr phEnum, uint td, uint[] rMethodBody, uint[] rMethodDecl, uint cMax, ref uint pcTokens)
        => VTable.EnumMethodImplsPtr(Self, ref phEnum, td, rMethodBody, rMethodDecl, cMax, ref pcTokens);

    public HResult EnumPermissionSets(ref IntPtr phEnum, uint tk, uint dwActions, uint[] rPermission, uint cMax, ref uint pcTokens)
        => VTable.EnumPermissionSetsPtr(Self, ref phEnum, tk, dwActions, rPermission, cMax, ref pcTokens);

    public HResult FindMember(uint td, ref ushort szName, ref byte pvSigBlob, uint cbSigBlob, ref uint pmb)
        => VTable.FindMemberPtr(Self, td, ref szName, ref pvSigBlob, cbSigBlob, ref pmb);

    public HResult FindMethod(uint td, ref ushort szName, ref byte pvSigBlob, uint cbSigBlob, ref uint pmb)
        => VTable.FindMethodPtr(Self, td, ref szName, ref pvSigBlob, cbSigBlob, ref pmb);

    public HResult FindField(uint td, ref ushort szName, ref byte pvSigBlob, uint cbSigBlob, ref uint pmb)
        => VTable.FindFieldPtr(Self, td, ref szName, ref pvSigBlob, cbSigBlob, ref pmb);

    public HResult FindMemberRef(uint td, ref ushort szName, ref byte pvSigBlob, uint cbSigBlob, ref uint pmr)
        => VTable.FindMemberRefPtr(Self, td, ref szName, ref pvSigBlob, cbSigBlob, ref pmr);

    public HResult GetMethodProps(uint mb, ref uint pClass, char* szMethod, uint cchMethod, ref uint pchMethod, ref uint pdwAttr, ref byte* ppvSigBlob, ref uint pcbSigBlob, ref uint pulCodeRVA, ref uint pdwImplFlags)
        => VTable.GetMethodPropsPtr(Self, mb, ref pClass, szMethod, cchMethod, ref pchMethod, ref pdwAttr, ref ppvSigBlob, ref pcbSigBlob, ref pulCodeRVA, ref pdwImplFlags);

    public HResult GetMemberRefProps(uint mr, ref uint ptk, char* szMember, uint cchMember, ref uint pchMember, ref byte* ppvSigBlob, ref uint pbSig)
        => VTable.GetMemberRefPropsPtr(Self, mr, ref ptk, szMember, cchMember, ref pchMember, ref ppvSigBlob, ref pbSig);

    public HResult EnumProperties(ref IntPtr phEnum, uint td, uint[] rProperties, uint cMax, ref uint pcProperties)
        => VTable.EnumPropertiesPtr(Self, ref phEnum, td, rProperties, cMax, ref pcProperties);

    public HResult EnumEvents(ref IntPtr phEnum, uint td, uint[] rEvents, uint cMax, ref uint pcEvents)
        => VTable.EnumEventsPtr(Self, ref phEnum, td, rEvents, cMax, ref pcEvents);

    public HResult GetEventProps(uint ev, ref uint pClass, ref ushort szEvent, uint cchEvent, ref uint pchEvent, ref uint pdwEventFlags, ref uint ptkEventType, ref uint pmdAddOn, ref uint pmdRemoveOn, ref uint pmdFire, uint[] rmdOtherMethod, uint cMax, ref uint pcOtherMethod)
        => VTable.GetEventPropsPtr(Self, ev, ref pClass, ref szEvent, cchEvent, ref pchEvent, ref pdwEventFlags, ref ptkEventType, ref pmdAddOn, ref pmdRemoveOn, ref pmdFire, rmdOtherMethod, cMax, ref pcOtherMethod);

    public HResult EnumMethodSemantics(ref IntPtr phEnum, uint mb, uint[] rEventProp, uint cMax, ref uint pcEventProp)
        => VTable.EnumMethodSemanticsPtr(Self, ref phEnum, mb, rEventProp, cMax, ref pcEventProp);

    public HResult GetMethodSemantics(uint mb, uint tkEventProp, ref uint pdwSemanticsFlags)
        => VTable.GetMethodSemanticsPtr(Self, mb, tkEventProp, ref pdwSemanticsFlags);

    public HResult GetClassLayout(uint td, ref uint pdwPackSize, COR_FIELD_OFFSET[] rFieldOffset, uint cMax, ref uint pcFieldOffset, ref uint pulClassSize)
        => VTable.GetClassLayoutPtr(Self, td, ref pdwPackSize, rFieldOffset, cMax, ref pcFieldOffset, ref pulClassSize);

    public HResult GetFieldMarshal(uint tk, ref byte* ppvNativeType, ref uint pcbNativeType)
        => VTable.GetFieldMarshalPtr(Self, tk, ref ppvNativeType, ref pcbNativeType);

    public HResult GetRVA(uint tk, ref uint pulCodeRVA, ref uint pdwImplFlags)
        => VTable.GetRVAPtr(Self, tk, ref pulCodeRVA, ref pdwImplFlags);

    public HResult GetPermissionSetProps(uint pm, ref uint pdwAction, ref IntPtr ppvPermission, ref uint pcbPermission)
        => VTable.GetPermissionSetPropsPtr(Self, pm, ref pdwAction, ref ppvPermission, ref pcbPermission);

    public HResult GetSigFromToken(uint mdSig, ref byte* ppvSig, ref uint pcbSig)
        => VTable.GetSigFromTokenPtr(Self, mdSig, ref ppvSig, ref pcbSig);

    public HResult GetModuleRefProps(uint mur, char* szName, uint cchName, ref uint pchName)
        => VTable.GetModuleRefPropsPtr(Self, mur, szName, cchName, ref pchName);

    public HResult EnumModuleRefs(ref IntPtr phEnum, uint[] rModuleRefs, uint cmax, ref uint pcModuleRefs)
        => VTable.EnumModuleRefsPtr(Self, ref phEnum, rModuleRefs, cmax, ref pcModuleRefs);

    public HResult GetTypeSpecFromToken(uint typespec, ref byte* ppvSig, ref uint pcbSig)
        => VTable.GetTypeSpecFromTokenPtr(Self, typespec, ref ppvSig, ref pcbSig);

    public HResult GetNameFromToken(uint tk, ref char* pszUtf8NamePtr)
        => VTable.GetNameFromTokenPtr(Self, tk, ref pszUtf8NamePtr);

    public HResult EnumUnresolvedMethods(ref IntPtr phEnum, uint[] rMethods, uint cMax, ref uint pcTokens)
        => VTable.EnumUnresolvedMethodsPtr(Self, ref phEnum, rMethods, cMax, ref pcTokens);

    public HResult GetUserString(uint stk, char* szString, uint cchString, ref uint pchString)
        => VTable.GetUserStringPtr(Self, stk, szString, cchString, ref pchString);

    public HResult GetPinvokeMap(uint tk, ref uint pdwMappingFlags, char* szImportName, uint cchImportName, ref uint pchImportName, ref uint pmrImportDLL)
        => VTable.GetPinvokeMapPtr(Self, tk, ref pdwMappingFlags, szImportName, cchImportName, ref pchImportName, ref pmrImportDLL);

    public HResult EnumSignatures(ref IntPtr phEnum, uint[] rSignatures, uint cmax, ref uint pcSignatures)
        => VTable.EnumSignaturesPtr(Self, ref phEnum, rSignatures, cmax, ref pcSignatures);

    public HResult EnumTypeSpecs(ref IntPtr phEnum, uint[] rTypeSpecs, uint cmax, ref uint pcTypeSpecs)
        => VTable.EnumTypeSpecsPtr(Self, ref phEnum, rTypeSpecs, cmax, ref pcTypeSpecs);

    public HResult EnumUserStrings(ref IntPtr phEnum, uint[] rStrings, uint cmax, ref uint pcStrings)
        => VTable.EnumUserStringsPtr(Self, ref phEnum, rStrings, cmax, ref pcStrings);

    public HResult GetParamForMethodIndex(uint md, uint ulParamSeq, ref uint ppd)
        => VTable.GetParamForMethodIndexPtr(Self, md, ulParamSeq, ref ppd);

    public HResult EnumCustomAttributes(ref IntPtr phEnum, uint tk, uint tkType, uint[] rCustomAttributes, uint cMax, ref uint pcCustomAttributes)
        => VTable.EnumCustomAttributesPtr(Self, ref phEnum, tk, tkType, rCustomAttributes, cMax, ref pcCustomAttributes);

    public HResult GetCustomAttributeProps(uint cv, ref uint ptkObj, ref uint ptkType, ref IntPtr ppBlob, ref uint pcbSize)
        => VTable.GetCustomAttributePropsPtr(Self, cv, ref ptkObj, ref ptkType, ref ppBlob, ref pcbSize);

    public HResult FindTypeRef(uint tkResolutionScope, ref ushort szName, ref uint ptr)
        => VTable.FindTypeRefPtr(Self, tkResolutionScope, ref szName, ref ptr);

    public HResult GetMemberProps(uint mb, ref uint pClass, char* szMember, uint cchMember, ref uint pchMember, ref uint pdwAttr, ref byte* ppvSigBlob, ref uint pcbSigBlob, ref uint pulCodeRVA, ref uint pdwImplFlags, ref uint pdwCPlusTypeFlag, ref IntPtr ppValue, ref uint pcchValue)
        => VTable.GetMemberPropsPtr(Self, mb, ref pClass, szMember, cchMember, ref pchMember, ref pdwAttr, ref ppvSigBlob, ref pcbSigBlob, ref pulCodeRVA, ref pdwImplFlags, ref pdwCPlusTypeFlag, ref ppValue, ref pcchValue);

    public HResult GetFieldProps(uint mb, ref uint pClass, char* szField, uint cchField, ref uint pchField, ref uint pdwAttr, ref byte* ppvSigBlob, ref uint pcbSigBlob, ref uint pdwCPlusTypeFlag, ref IntPtr ppValue, ref uint pcchValue)
        => VTable.GetFieldPropsPtr(Self, mb, ref pClass, szField, cchField, ref pchField, ref pdwAttr, ref ppvSigBlob, ref pcbSigBlob, ref pdwCPlusTypeFlag, ref ppValue, ref pcchValue);

    public HResult GetPropertyProps(uint prop, ref uint pClass, ref ushort szProperty, uint cchProperty, ref uint pchProperty, ref uint pdwPropFlags, ref byte* ppvSig, ref uint pbSig, ref uint pdwCPlusTypeFlag, ref IntPtr ppDefaultValue, ref uint pcchDefaultValue, ref uint pmdSetter, ref uint pmdGetter, uint[] rmdOtherMethod, uint cMax, ref uint pcOtherMethod)
        => VTable.GetPropertyPropsPtr(Self, prop, ref pClass, ref szProperty, cchProperty, ref pchProperty, ref pdwPropFlags, ref ppvSig, ref pbSig, ref pdwCPlusTypeFlag, ref ppDefaultValue, ref pcchDefaultValue, ref pmdSetter, ref pmdGetter, rmdOtherMethod, cMax, ref pcOtherMethod);

    public HResult GetParamProps(uint tk, ref uint pmd, ref uint pulSequence, char* szName, uint cchName, ref uint pchName, ref uint pdwAttr, ref uint pdwCPlusTypeFlag, ref IntPtr ppValue, ref uint pcchValue)
        => VTable.GetParamPropsPtr(Self, tk, ref pmd, ref pulSequence, szName, cchName, ref pchName, ref pdwAttr, ref pdwCPlusTypeFlag, ref ppValue, ref pcchValue);

    public HResult GetCustomAttributeByName(uint tkObj, ref ushort szName, ref IntPtr ppData, ref uint pcbData)
        => VTable.GetCustomAttributeByNamePtr(Self, tkObj, ref szName, ref ppData, ref pcbData);

    public bool IsValidToken(uint tk)
        => VTable.IsValidTokenPtr(Self, tk);

    public HResult GetNestedClassProps(uint tdNestedClass, ref uint ptdEnclosingClass)
        => VTable.GetNestedClassPropsPtr(Self, tdNestedClass, ref ptdEnclosingClass);

    public HResult GetNativeCallConvFromSig(IntPtr pvSig, uint cbSig, ref uint pCallConv)
        => VTable.GetNativeCallConvFromSigPtr(Self, pvSig, cbSig, ref pCallConv);

    public HResult IsGlobal(uint pd, ref int pbGlobal)
        => VTable.IsGlobalPtr(Self, pd, ref pbGlobal);

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct IMetaDataImportVTable
    {
        public readonly delegate* unmanaged[Stdcall]<IntPtr, IntPtr, void> CloseEnumPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, IntPtr, ref uint, HResult> CountEnumPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, IntPtr, uint, HResult> ResetEnumPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref IntPtr, uint[], uint, ref uint, HResult> EnumTypeDefsPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref IntPtr, uint, uint[], uint, ref uint, HResult> EnumInterfaceImplsPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref IntPtr, uint[], uint, ref uint, HResult> EnumTypeRefsPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref ushort, uint, ref uint, HResult> FindTypeDefByNamePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, char*, uint, ref uint, ref Guid, HResult> GetScopePropsPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref uint, HResult> GetModuleFromScopePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, char*, uint, ref uint, ref uint, ref uint, HResult> GetTypeDefPropsPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, ref uint, ref uint, HResult> GetInterfaceImplPropsPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, ref uint, char*, uint, ref uint, HResult> GetTypeRefPropsPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, ref Guid, ref IntPtr, ref uint, HResult> ResolveTypeRefPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref IntPtr, uint, uint[], uint, ref uint, HResult> EnumMembersPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref IntPtr, uint, ref ushort, uint[], uint, ref uint, HResult> EnumMembersWithNamePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref IntPtr, uint, uint[], uint, ref uint, HResult> EnumMethodsPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref IntPtr, uint, ref ushort, uint[], uint, ref uint, HResult> EnumMethodsWithNamePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref IntPtr, uint, uint[], uint, ref uint, HResult> EnumFieldsPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref IntPtr, uint, ref ushort, uint[], uint, ref uint, HResult> EnumFieldsWithNamePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref IntPtr, uint, uint[], uint, ref uint, HResult> EnumParamsPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref IntPtr, uint, uint[], uint, ref uint, HResult> EnumMemberRefsPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref IntPtr, uint, uint[], uint[], uint, ref uint, HResult> EnumMethodImplsPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref IntPtr, uint, uint, uint[], uint, ref uint, HResult> EnumPermissionSetsPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, ref ushort, ref byte, uint, ref uint, HResult> FindMemberPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, ref ushort, ref byte, uint, ref uint, HResult> FindMethodPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, ref ushort, ref byte, uint, ref uint, HResult> FindFieldPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, ref ushort, ref byte, uint, ref uint, HResult> FindMemberRefPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, ref uint, char*, uint, ref uint, ref uint, ref byte*, ref uint, ref uint, ref uint, HResult> GetMethodPropsPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, ref uint, char*, uint, ref uint, ref byte*, ref uint, HResult> GetMemberRefPropsPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref IntPtr, uint, uint[], uint, ref uint, HResult> EnumPropertiesPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref IntPtr, uint, uint[], uint, ref uint, HResult> EnumEventsPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, ref uint, ref ushort, uint, ref uint, ref uint, ref uint, ref uint, ref uint, ref uint, uint[], uint, ref uint, HResult> GetEventPropsPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref IntPtr, uint, uint[], uint, ref uint, HResult> EnumMethodSemanticsPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, uint, ref uint, HResult> GetMethodSemanticsPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, ref uint, COR_FIELD_OFFSET[], uint, ref uint, ref uint, HResult> GetClassLayoutPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, ref byte*, ref uint, HResult> GetFieldMarshalPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, ref uint, ref uint, HResult> GetRVAPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, ref uint, ref IntPtr, ref uint, HResult> GetPermissionSetPropsPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, ref byte*, ref uint, HResult> GetSigFromTokenPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, char*, uint, ref uint, HResult> GetModuleRefPropsPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref IntPtr, uint[], uint, ref uint, HResult> EnumModuleRefsPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, ref byte*, ref uint, HResult> GetTypeSpecFromTokenPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, ref char*, HResult> GetNameFromTokenPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref IntPtr, uint[], uint, ref uint, HResult> EnumUnresolvedMethodsPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, char*, uint, ref uint, HResult> GetUserStringPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, ref uint, char*, uint, ref uint, ref uint, HResult> GetPinvokeMapPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref IntPtr, uint[], uint, ref uint, HResult> EnumSignaturesPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref IntPtr, uint[], uint, ref uint, HResult> EnumTypeSpecsPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref IntPtr, uint[], uint, ref uint, HResult> EnumUserStringsPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, uint, ref uint, HResult> GetParamForMethodIndexPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref IntPtr, uint, uint, uint[], uint, ref uint, HResult> EnumCustomAttributesPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, ref uint, ref uint, ref IntPtr, ref uint, HResult> GetCustomAttributePropsPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, ref ushort, ref uint, HResult> FindTypeRefPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, ref uint, char*, uint, ref uint, ref uint, ref byte*, ref uint, ref uint, ref uint, ref uint, ref IntPtr, ref uint, HResult> GetMemberPropsPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, ref uint, char*, uint, ref uint, ref uint, ref byte*, ref uint, ref uint, ref IntPtr, ref uint, HResult> GetFieldPropsPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, ref uint, ref ushort, uint, ref uint, ref uint, ref byte*, ref uint, ref uint, ref IntPtr, ref uint, ref uint, ref uint, uint[], uint, ref uint, HResult> GetPropertyPropsPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, ref uint, ref uint, char*, uint, ref uint, ref uint, ref uint, ref IntPtr, ref uint, HResult> GetParamPropsPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, ref ushort, ref IntPtr, ref uint, HResult> GetCustomAttributeByNamePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, bool> IsValidTokenPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, ref uint, HResult> GetNestedClassPropsPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, IntPtr, uint, ref uint, HResult> GetNativeCallConvFromSigPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, ref int, HResult> IsGlobalPtr;
    }
}


[StructLayout(LayoutKind.Explicit)]
unsafe struct COR_FIELD_OFFSET
{
    [FieldOffset(0)]
    public uint ridOfField;
    [FieldOffset(32)]
    public uint ulOffset;
}

