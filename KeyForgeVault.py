import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import random
import string
import json
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os

class PasswordGenerator:
    def __init__(self, root):
        self.root = root
        self.root.title("KeyForge")
        self.root.geometry("800x650")
        self.root.minsize(750, 600)
        self.root.resizable(True, True)
        
        # Clave de encriptación
        self.key = self.generate_key()
        self.cipher_suite = Fernet(self.key)
        
        self.setup_ui()
        self.load_passwords()
    
    def generate_key(self):
        """Genera o carga una clave de encriptación"""
        key_file = 'encryption_key.key'
        if os.path.exists(key_file):
            with open(key_file, 'rb') as f:
                return f.read()
        else:
            key = Fernet.generate_key()
            with open(key_file, 'wb') as f:
                f.write(key)
            return key
    
    def setup_ui(self):
        # Crear un frame principal con scrollbar
        main_frame = ttk.Frame(self.root, padding="15")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configurar grid weights para que sea responsive
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.columnconfigure(2, weight=1)
        
        # Título
        title_label = ttk.Label(main_frame, text="KeyForge Vault", 
                               font=("Arial", 16, "bold"))
        title_label.grid(row=0, column=0, columnspan=4, pady=(0, 20))
        
        # Configuración de la contraseña
        ttk.Label(main_frame, text="Longitud:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.length_var = tk.IntVar(value=12)
        length_spinbox = ttk.Spinbox(main_frame, from_=8, to=32, 
                                    textvariable=self.length_var, width=10)
        length_spinbox.grid(row=1, column=1, sticky=tk.W, pady=5)
        
        # Checkboxes para tipos de caracteres - EN LA MISMA FILA
        self.upper_var = tk.BooleanVar(value=True)
        self.lower_var = tk.BooleanVar(value=True)
        self.digits_var = tk.BooleanVar(value=True)
        self.symbols_var = tk.BooleanVar(value=True)
        
        # Frame para contener los checkboxes en horizontal
        checkbox_frame = ttk.Frame(main_frame)
        checkbox_frame.grid(row=2, column=0, columnspan=4, sticky=(tk.W, tk.E), pady=10)
        
        # Configurar pesos para distribución equitativa
        for i in range(12):
            checkbox_frame.columnconfigure(i, weight=1)
        
        # Checkboxes distribuidos horizontalmente
        ttk.Checkbutton(checkbox_frame, text="Mayúsculas", 
                       variable=self.upper_var).grid(row=0, column=0, sticky=tk.W, padx=5)
        ttk.Checkbutton(checkbox_frame, text="Minúsculas", 
                       variable=self.lower_var).grid(row=0, column=1, sticky=tk.W, padx=5)
        ttk.Checkbutton(checkbox_frame, text="Números", 
                       variable=self.digits_var).grid(row=0, column=2, sticky=tk.W, padx=5)
        ttk.Checkbutton(checkbox_frame, text="Símbolos", 
                       variable=self.symbols_var).grid(row=0, column=3, sticky=tk.W, padx=5)
        
        # Botón generar
        generate_btn = ttk.Button(main_frame, text="Generar Contraseña", 
                                 command=self.generate_password)
        generate_btn.grid(row=3, column=0, columnspan=2, pady=15)
        
        # Contraseña generada
        ttk.Label(main_frame, text="Contraseña:").grid(row=4, column=0, sticky=tk.W, pady=5)
        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(main_frame, textvariable=self.password_var, 
                                       show="*", width=35, font=("Courier", 14))
        self.password_entry.grid(row=4, column=1, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        # Botón para mostrar/ocultar contraseña
        self.show_var = tk.BooleanVar(value=False)
        show_btn = ttk.Checkbutton(main_frame, text="Mostrar", 
                                  variable=self.show_var, 
                                  command=self.toggle_password_visibility)
        show_btn.grid(row=4, column=3, padx=(10, 0))
        
        # Nombre para la contraseña
        ttk.Label(main_frame, text="Servicio:").grid(row=5, column=0, sticky=tk.W, pady=5)
        self.name_var = tk.StringVar()
        name_entry = ttk.Entry(main_frame, textvariable=self.name_var, width=35)
        name_entry.grid(row=5, column=1, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        # Usuario/Email
        ttk.Label(main_frame, text="Usuario/Email:").grid(row=6, column=0, sticky=tk.W, pady=5)
        self.username_var = tk.StringVar()
        username_entry = ttk.Entry(main_frame, textvariable=self.username_var, width=35)
        username_entry.grid(row=6, column=1, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        # Botón guardar
        save_btn = ttk.Button(main_frame, text="Guardar Contraseña", 
                             command=self.save_password)
        save_btn.grid(row=7, column=0, columnspan=2, pady=15)
        
        # Separador
        separator = ttk.Separator(main_frame, orient='horizontal')
        separator.grid(row=8, column=0, columnspan=4, sticky=(tk.W, tk.E), pady=20)
        
        # Lista de contraseñas guardadas
        ttk.Label(main_frame, text="Contraseñas Guardadas:", 
                 font=("Arial", 12, "bold")).grid(row=9, column=0, 
                                                 columnspan=4, pady=(0, 10), sticky=tk.W)
        
        # Frame para el treeview y scrollbar
        tree_frame = ttk.Frame(main_frame)
        tree_frame.grid(row=10, column=0, columnspan=4, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        tree_frame.columnconfigure(0, weight=1)
        tree_frame.rowconfigure(0, weight=1)
        
        # Treeview para mostrar contraseñas guardadas
        columns = ('Servicio', 'Usuario', 'Contraseña')
        self.tree = ttk.Treeview(tree_frame, columns=columns, 
                                show='headings', height=8)
        
        self.tree.heading('Servicio', text='Servicio')
        self.tree.heading('Usuario', text='Usuario/Email')
        self.tree.heading('Contraseña', text='Contraseña')
        
        self.tree.column('Servicio', width=200, minwidth=120)
        self.tree.column('Usuario', width=200, minwidth=120)
        self.tree.column('Contraseña', width=150, minwidth=100)
        
        self.tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Scrollbar para el treeview
        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, 
                                 command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.grid(row=0, column=1, sticky='ns')
        
        # Botones para las contraseñas guardadas
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=11, column=0, columnspan=4, pady=10)
        
        ttk.Button(button_frame, text="Ver Contraseña", 
                  command=self.view_password).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Copiar Contraseña", 
                  command=self.copy_password).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Copiar Usuario", 
                  command=self.copy_username).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Eliminar", 
                  command=self.delete_password).pack(side=tk.LEFT, padx=5)
        
        # Configurar weights para que los elementos se expandan
        for i in range(12):
            main_frame.rowconfigure(i, weight=0)
        main_frame.rowconfigure(10, weight=1)  # Treeview se expande
        
        for i in range(4):
            main_frame.columnconfigure(i, weight=0)
        main_frame.columnconfigure(1, weight=1)
        main_frame.columnconfigure(2, weight=1)
    
    def toggle_password_visibility(self):
        """Alterna entre mostrar y ocultar la contraseña"""
        if self.show_var.get():
            self.password_entry.config(show='')
        else:
            self.password_entry.config(show='*')
    
    def generate_password(self):
        """Genera una contraseña segura basada en las preferencias del usuario"""
        length = self.length_var.get()
        
        # Definir los conjuntos de caracteres disponibles
        character_sets = []
        
        if self.upper_var.get():
            character_sets.append(string.ascii_uppercase)
        if self.lower_var.get():
            character_sets.append(string.ascii_lowercase)
        if self.digits_var.get():
            character_sets.append(string.digits)
        if self.symbols_var.get():
            character_sets.append(string.punctuation)
        
        if not character_sets:
            messagebox.showerror("Error", "Selecciona al menos un tipo de carácter")
            return
        
        # Asegurar que la contraseña tenga al menos un carácter de cada tipo seleccionado
        password = []
        for char_set in character_sets:
            password.append(random.choice(char_set))
        
        # Completar la contraseña con caracteres aleatorios
        all_chars = ''.join(character_sets)
        password.extend(random.choices(all_chars, k=length - len(password)))
        
        # Mezclar la contraseña
        random.shuffle(password)
        final_password = ''.join(password)
        
        self.password_var.set(final_password)
    
    def save_password(self):
        """Guarda la contraseña con nombre y usuario"""
        password = self.password_var.get()
        service_name = self.name_var.get().strip()
        username = self.username_var.get().strip()
        
        if not password:
            messagebox.showerror("Error", "Primero genera una contraseña")
            return
        
        if not service_name:
            messagebox.showerror("Error", "Ingresa un nombre para el servicio")
            return
        
        if not username:
            messagebox.showerror("Error", "Ingresa un usuario o email")
            return
        
        # Cifrar la contraseña antes de guardarla
        encrypted_password = self.encrypt_data(password)
        
        # Guardar en el archivo
        try:
            with open('passwords.bin', 'ab') as f:
                data = {
                    'service': service_name,
                    'username': username,
                    'password': encrypted_password.decode()
                }
                f.write(json.dumps(data).encode() + b'\n')
            
            messagebox.showinfo("Éxito", "Contraseña guardada correctamente")
            self.name_var.set('')
            self.username_var.set('')
            self.load_passwords()
            
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo guardar: {str(e)}")
    
    def encrypt_data(self, data):
        """Cifra los datos"""
        return self.cipher_suite.encrypt(data.encode())
    
    def decrypt_data(self, encrypted_data):
        """Descifra los datos"""
        return self.cipher_suite.decrypt(encrypted_data.encode()).decode()
    
    def load_passwords(self):
        """Carga las contraseñas guardadas"""
        # Limpiar el treeview
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        # Cargar contraseñas del archivo
        if os.path.exists('passwords.bin'):
            try:
                with open('passwords.bin', 'rb') as f:
                    for line in f:
                        data = json.loads(line.decode().strip())
                        self.tree.insert('', 'end', values=(
                            data['service'], 
                            data['username'],
                            '••••••••'  # Mostrar contraseña oculta
                        ))
            except Exception as e:
                messagebox.showerror("Error", f"No se pudieron cargar las contraseñas: {str(e)}")
    
    def view_password(self):
        """Muestra la contraseña seleccionada"""
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showwarning("Advertencia", "Selecciona una contraseña primero")
            return
        
        item = self.tree.item(selected_item[0])
        service_name = item['values'][0]
        username = item['values'][1]
        
        # Buscar y descifrar la contraseña
        if os.path.exists('passwords.bin'):
            try:
                with open('passwords.bin', 'rb') as f:
                    for line in f:
                        data = json.loads(line.decode().strip())
                        if data['service'] == service_name and data['username'] == username:
                            decrypted_password = self.decrypt_data(data['password'])
                            messagebox.showinfo(
                                "Contraseña", 
                                f"Servicio: {service_name}\nUsuario: {username}\nContraseña: {decrypted_password}"
                            )
                            return
                
                messagebox.showerror("Error", "Contraseña no encontrada")
                
            except Exception as e:
                messagebox.showerror("Error", f"No se pudo leer la contraseña: {str(e)}")
    
    def copy_password(self):
        """Copia la contraseña seleccionada al portapapeles"""
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showwarning("Advertencia", "Selecciona una contraseña primero")
            return
        
        item = self.tree.item(selected_item[0])
        service_name = item['values'][0]
        username = item['values'][1]
        
        # Buscar y descifrar la contraseña
        if os.path.exists('passwords.bin'):
            try:
                with open('passwords.bin', 'rb') as f:
                    for line in f:
                        data = json.loads(line.decode().strip())
                        if data['service'] == service_name and data['username'] == username:
                            decrypted_password = self.decrypt_data(data['password'])
                            self.root.clipboard_clear()
                            self.root.clipboard_append(decrypted_password)
                            messagebox.showinfo("Éxito", "Contraseña copiada al portapapeles")
                            return
                
                messagebox.showerror("Error", "Contraseña no encontrada")
                
            except Exception as e:
                messagebox.showerror("Error", f"No se pudo copiar la contraseña: {str(e)}")
    
    def copy_username(self):
        """Copia el usuario seleccionado al portapapeles"""
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showwarning("Advertencia", "Selecciona una contraseña primero")
            return
        
        item = self.tree.item(selected_item[0])
        username = item['values'][1]
        
        self.root.clipboard_clear()
        self.root.clipboard_append(username)
        messagebox.showinfo("Éxito", "Usuario copiado al portapapeles")
    
    def delete_password(self):
        """Elimina la contraseña seleccionada"""
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showwarning("Advertencia", "Selecciona una contraseña primero")
            return
        
        item = self.tree.item(selected_item[0])
        service_name = item['values'][0]
        username = item['values'][1]
        
        if messagebox.askyesno("Confirmar", f"¿Estás seguro de eliminar '{service_name}' - '{username}'?"):
            # Recrear el archivo sin la contraseña a eliminar
            try:
                if os.path.exists('passwords.bin'):
                    temp_lines = []
                    with open('passwords.bin', 'rb') as f:
                        for line in f:
                            data = json.loads(line.decode().strip())
                            if not (data['service'] == service_name and data['username'] == username):
                                temp_lines.append(line)
                    
                    with open('passwords.bin', 'wb') as f:
                        for line in temp_lines:
                            f.write(line)
                    
                    messagebox.showinfo("Éxito", "Contraseña eliminada")
                    self.load_passwords()
                
            except Exception as e:
                messagebox.showerror("Error", f"No se pudo eliminar: {str(e)}")

def main():
    root = tk.Tk()
    app = PasswordGenerator(root)
    root.mainloop()

if __name__ == "__main__":
    main()