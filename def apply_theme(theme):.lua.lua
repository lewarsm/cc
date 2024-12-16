def apply_theme(theme):
    style = ttk.Style()
    colors = NORD_STYLES[theme]
    style.configure("TFrame", background=colors["background"])
    style.configure("TLabelFrame", background=colors["background"], foreground=colors["foreground"])
    style.configure("Treeview", background=colors["background"], foreground=colors["foreground"], fieldbackground=colors["background"])
    style.configure("Treeview.Heading", background=colors["header"], foreground=colors["foreground"])
    style.configure("TButton", background=colors["button"], foreground=colors["foreground"])
    style.map("TButton", background=[("active", colors["highlight"])])
    style.configure("TEntry", background=colors["background"], foreground=colors["foreground"], fieldbackground=colors["background"])
    style.configure("TText", background=colors["background"], foreground=colors["foreground"])
    style.configure("Invert.TButton", background=colors["invert_button"], foreground=colors["foreground"])
    style.map("Invert.TButton", background=[("active", colors["highlight"])])


    "background": "#304CB2",
    "foreground": "#D8DEE9",
    "highlight": "#88C0D0",
    "error": "#BF616A",
    "header": "#4C566A",
    "row_odd": "#3B4252",
    "row_even": "#434C5E",
    "button": "#FFCA4F",
    "invert_button": "#BF616A"


    