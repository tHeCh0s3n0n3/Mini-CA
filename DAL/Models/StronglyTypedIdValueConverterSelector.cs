using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using System.Collections.Concurrent;

namespace DAL.Models;
public class StronglyTypedIdValueConverterSelector : ValueConverterSelector
{
    // The dictionary in the base type is private, so we need our own one here.
    private readonly ConcurrentDictionary<(Type ModelClrType
                                           , Type ProviderClrType)
                                          , ValueConverterInfo> _converters
        = new();

    public StronglyTypedIdValueConverterSelector(ValueConverterSelectorDependencies dependencies)
        : base(dependencies)
    { }

    public override IEnumerable<ValueConverterInfo> Select(Type modelClrType
                                                           , Type providerClrType = null)
    {
        foreach (ValueConverterInfo converter in base.Select(modelClrType, providerClrType))
        {
            yield return converter;
        }

        // Extract the "real" type T from Nullable<T> if required
        Type underlyingModelType = UnwrapNullableType(modelClrType);
        Type underlyingProviderType = UnwrapNullableType(providerClrType);

        // 'null' means 'get any value converters for the modelClrType'
        if (underlyingProviderType is null
            || underlyingProviderType.Equals(typeof(Guid)))
        {
            // Try and get a nested class with the expected name. 
            Type converterType = underlyingModelType.GetNestedType("EfCoreValueConverter");

            if (converterType is not null)
            {
                yield return this._converters.GetOrAdd(
                    (underlyingModelType, typeof(Guid)),
                    k =>
                    {
                        // Create an instance of the converter whenever it's requested.
                        ValueConverter factory(ValueConverterInfo info)
                            => (ValueConverter)Activator.CreateInstance(converterType, info.MappingHints);

                        // Build the info for our strongly-typed ID => Guid converter
                        return new ValueConverterInfo(modelClrType, typeof(Guid), factory);
                    }
                );
            }
        }
    }

    private static Type UnwrapNullableType(Type type)
    {
        if (type is null) { return null; }

        return Nullable.GetUnderlyingType(type) ?? type;
    }
}