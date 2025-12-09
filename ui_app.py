import tkinter as tk
from tkinter import ttk, messagebox
from typing import Dict, List

from utils.storage import ensure_data_store, authenticate, list_records, save_records
from company_profile.company_info import show_company_profile
from company_profile.asset_inventory import assets as default_assets
from risk_analysis.threat_vulnerability import matrix as default_threats
from risk_analysis.security_controls import show_security_controls
from compliance.legal_ethics import show_compliance
from business_impact.bia_analysis import bia as default_bia
from cryptography_demo.encryption_demo import demo_encryption


def _text_from_func(func) -> str:
    import io, sys
    buf = io.StringIO()
    old_out = sys.stdout
    try:
        sys.stdout = buf
        func()
    finally:
        sys.stdout = old_out
    return buf.getvalue()


class LoginWindow(tk.Toplevel):
    def __init__(self, master, on_success):
        super().__init__(master)
        self.title("Secure Login")
        self.resizable(False, False)
        self.on_success = on_success

        ttk.Label(self, text="Username").grid(row=0, column=0, padx=8, pady=6, sticky="e")
        ttk.Label(self, text="Password").grid(row=1, column=0, padx=8, pady=6, sticky="e")
        self.username = ttk.Entry(self)
        self.password = ttk.Entry(self, show="*")
        self.username.grid(row=0, column=1, padx=8, pady=6)
        self.password.grid(row=1, column=1, padx=8, pady=6)

        btn = ttk.Button(self, text="Login", command=self.try_login)
        btn.grid(row=2, column=0, columnspan=2, pady=8)
        self.bind("<Return>", lambda e: self.try_login())
        self.grab_set()
        self.username.focus_set()

    def try_login(self):
        user = self.username.get().strip()
        pwd = self.password.get()
        if authenticate(user, pwd):
            self.on_success(user)
            self.destroy()
        else:
            messagebox.showerror("Access denied", "Invalid credentials")


class CRUDTab(ttk.Frame):
    def __init__(self, master, kind: str, columns: List[str], seed: List[Dict] | None = None):
        super().__init__(master)
        self.kind = kind
        self.columns = columns

        # Header controls
        header = ttk.Frame(self)
        header.pack(fill="x", padx=8, pady=6)
        ttk.Label(header, text=f"{kind.capitalize()} Records", font=("Segoe UI", 11, "bold")).pack(side="left")
        ttk.Button(header, text="Add", command=self.add_record).pack(side="right", padx=4)
        ttk.Button(header, text="Edit", command=self.edit_record).pack(side="right", padx=4)
        ttk.Button(header, text="Delete", command=self.delete_record).pack(side="right", padx=4)
        ttk.Button(header, text="Reload", command=self.reload).pack(side="right", padx=4)

        # Table
        self.tree = ttk.Treeview(self, columns=columns, show="headings", height=12)
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=150, anchor="center")
        self.tree.pack(fill="both", expand=True, padx=8, pady=6)

        # Seed default data if file is empty
        current = list_records(self.kind)
        if seed and not current:
            save_records(self.kind, seed)

        self.reload()

    def reload(self):
        for row in self.tree.get_children():
            self.tree.delete(row)
        for item in list_records(self.kind):
            values = [item.get(col, "") for col in self.columns]
            self.tree.insert("", "end", values=values)

    def _open_form(self, title: str, init: Dict[str, str] | None = None) -> Dict[str, str] | None:
        win = tk.Toplevel(self)
        win.title(title)
        win.resizable(False, False)
        entries: Dict[str, tk.Entry] = {}
        for idx, col in enumerate(self.columns):
            ttk.Label(win, text=col).grid(row=idx, column=0, padx=8, pady=6, sticky="e")
            ent = ttk.Entry(win)
            ent.grid(row=idx, column=1, padx=8, pady=6)
            if init and col in init:
                ent.insert(0, str(init[col]))
            entries[col] = ent

        result: Dict[str, str] | None = {col: "" for col in self.columns}

        def on_ok():
            for col, ent in entries.items():
                result[col] = ent.get().strip()
            win.destroy()

        def on_cancel():
            nonlocal result
            result = None
            win.destroy()

        btns = ttk.Frame(win)
        btns.grid(row=len(self.columns), column=0, columnspan=2, pady=8)
        ttk.Button(btns, text="Cancel", command=on_cancel).pack(side="right", padx=4)
        ttk.Button(btns, text="Save", command=on_ok).pack(side="right", padx=4)
        win.transient(self)
        win.grab_set()
        win.wait_window()
        return result

    def add_record(self):
        data = self._open_form(f"Add {self.kind[:-1].capitalize()}")
        if not data:
            return
        
        # Validate that required fields are not empty
        empty_fields = [col for col, val in data.items() if not val.strip()]
        if empty_fields:
            messagebox.showerror("Validation Error", f"Please fill in all required fields: {', '.join(empty_fields)}")
            return
        
        try:
            items = list_records(self.kind)
            items.append(data)
            save_records(self.kind, items)
            self.reload()
            messagebox.showinfo("Success", "Record added successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to add record: {str(e)}")

    def edit_record(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("Select", "Select a row to edit.")
            return
        values = self.tree.item(sel[0], "values")
        existing = {col: values[i] for i, col in enumerate(self.columns)}
        updated = self._open_form(f"Edit {self.kind[:-1].capitalize()}", init=existing)
        if not updated:
            return
        items = list_records(self.kind)
        # find by full match
        for i, it in enumerate(items):
            if all(str(it.get(col, "")) == str(existing[col]) for col in self.columns):
                items[i] = updated
                break
        save_records(self.kind, items)
        self.reload()

    def delete_record(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("Select", "Select a row to delete.")
            return
        if not messagebox.askyesno("Confirm", "Delete selected record?"):
            return
        values = self.tree.item(sel[0], "values")
        target = {col: values[i] for i, col in enumerate(self.columns)}
        items = list_records(self.kind)
        items = [it for it in items if not all(str(it.get(col, "")) == str(target[col]) for col in self.columns)]
        save_records(self.kind, items)
        self.reload()


class TextTab(ttk.Frame):
    def __init__(self, master, content: str):
        super().__init__(master)
        txt = tk.Text(self, wrap="word", height=20)
        txt.pack(fill="both", expand=True)
        txt.insert("1.0", content)
        txt.configure(state="disabled")


class CryptoTab(ttk.Frame):
    def __init__(self, master):
        super().__init__(master)
        self.output = tk.Text(self, wrap="word", height=18)
        self.output.pack(fill="both", expand=True, padx=8, pady=8)
        ttk.Button(self, text="Run Encryption Demo", command=self.run_demo).pack(pady=6)

    def run_demo(self):
        import io, sys
        buf = io.StringIO()
        old_out = sys.stdout
        try:
            sys.stdout = buf
            demo_encryption()
        finally:
            sys.stdout = old_out
        self.output.configure(state="normal")
        self.output.delete("1.0", tk.END)
        self.output.insert("1.0", buf.getvalue())
        self.output.configure(state="disabled")


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        ensure_data_store()
        self.title("Tech-Care Hospital – Enterprise Security Simulator")
        self.geometry("1000x650")
        self._user = None

        # show login first
        self.withdraw()
        LoginWindow(self, self._on_login)

    def _on_login(self, user):
        self._user = user
        self.deiconify()
        self._build_ui()

    def _build_ui(self):
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True)

        # Company Profile & Security Controls & Compliance
        profile_text = _text_from_func(show_company_profile)
        controls_text = _text_from_func(show_security_controls)
        compliance_text = _text_from_func(show_compliance)
        combined = f"Company Profile\n\n{profile_text}\nSecurity Controls\n\n{controls_text}\nCompliance\n\n{compliance_text}"
        nb.add(TextTab(nb, combined), text="Overview")

        # Assets CRUD
        assets_cols = ["Asset Name", "Type", "Value", "Owner", "Security Classification"]
        nb.add(CRUDTab(nb, "assets", assets_cols, seed=default_assets), text="Assets")

        # Threats CRUD
        threats_cols = ["Threat", "Vulnerability", "Likelihood", "Impact", "Countermeasure"]
        nb.add(CRUDTab(nb, "threats", threats_cols, seed=default_threats), text="Threats")

        # Incidents CRUD
        incidents_cols = ["Incident Type", "Date & Time", "Affected Systems", "Actions Taken", "Status"]
        nb.add(CRUDTab(nb, "incidents", incidents_cols, seed=[]), text="Incidents")

        # BIA CRUD
        bia_cols = ["Asset", "Threat Scenario", "Financial Impact", "Operational Impact", "Recovery Strategy"]
        nb.add(CRUDTab(nb, "bia", bia_cols, seed=default_bia), text="BIA")

        # Crypto Demo
        nb.add(CryptoTab(nb), text="Crypto Demo")

        # Footer: current user
        status = ttk.Label(self, text=f"Tech-Care Hospital — \"Your health Is Your Wealth. We Protect Both\"    |    Logged in as: {self._user}", anchor="w")
        status.pack(fill="x", padx=8, pady=4)


def main():
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
