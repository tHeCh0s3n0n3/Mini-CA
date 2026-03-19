namespace Backend;

public static class ExtensionMethods
{

    public static void AddIfNotFalse<T>(this ICollection<T> collection, bool condition, T? item)
    {
        if (condition
            && item is not null)
        {
            collection.Add(item);
        }
    }
}
