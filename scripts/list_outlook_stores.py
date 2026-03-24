import win32com.client


def main():
    outlook = win32com.client.Dispatch("Outlook.Application")
    namespace = outlook.GetNamespace("MAPI")

    print("Raices visibles en Outlook:\n")
    for i in range(1, namespace.Folders.Count + 1):
        root = namespace.Folders.Item(i)
        print("{0}. {1}".format(i, root.Name))
        try:
            print("   Subcarpetas:")
            max_show = min(root.Folders.Count, 10)
            for j in range(1, max_show + 1):
                print("     - {0}".format(root.Folders.Item(j).Name))
        except Exception as exc:
            print("   (No se pudieron listar subcarpetas: {0})".format(exc))
        print()


if __name__ == "__main__":
    main()
