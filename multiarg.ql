import cpp

Type getParameterTypeElement(Parameter p) {
  result = p.getUnspecifiedType()
  or
  result = getParameterTypeElement(p).(PointerType).getBaseType().getUnspecifiedType()
}

Type getParameterBaseType(Parameter p) {
  result = getParameterTypeElement(p) and not result instanceof PointerType
}

from Function f, Parameter p, Type baseType
where p = f.getAParameter() and
baseType = getParameterBaseType(p)
and not baseType instanceof Struct
select f, p
