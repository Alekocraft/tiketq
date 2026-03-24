import os
import win32com.client

MAILBOX_NAME = os.getenv("OUTLOOK_MAILBOX_NAME", "").strip()
MAX_ITEMS = 5


def get_inbox(namespace, mailbox_name=None):
    if mailbox_name:
        wanted = mailbox_name.lower()
        for i in range(1, namespace.Folders.Count + 1):
            root = namespace.Folders.Item(i)
            if (root.Name or "").strip().lower() == wanted:
                for j in range(1, root.Folders.Count + 1):
                    sub = root.Folders.Item(j)
                    if (sub.Name or "").strip().lower() in ("inbox", "bandeja de entrada"):
                        return sub
    return namespace.GetDefaultFolder(6)


def main():
    outlook = win32com.client.Dispatch("Outlook.Application")
    namespace = outlook.GetNamespace("MAPI")

    inbox = get_inbox(namespace, MAILBOX_NAME or None)
    items = inbox.Items
    items.Sort("[ReceivedTime]", True)

    print("Inbox:", inbox.Name)
    print("Total items:", items.Count)

    shown = 0
    for item in items:
        if item.Class == 43:
            print("=" * 80)
            print("Subject :", getattr(item, "Subject", ""))
            print("From    :", getattr(item, "SenderName", ""))
            print("Received:", getattr(item, "ReceivedTime", ""))
            print("Unread  :", getattr(item, "UnRead", ""))
            shown += 1
            if shown >= MAX_ITEMS:
                break


if __name__ == "__main__":
    main()
