global using Common;
global using StronglyTypedIds;

[assembly:StronglyTypedIdDefaults(converters: StronglyTypedIdConverter.TypeConverter
                                              | StronglyTypedIdConverter.SystemTextJson
                                              | StronglyTypedIdConverter.EfCoreValueConverter)]