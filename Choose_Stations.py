import json
import tkinter as tk
from tkinter import messagebox

# Function to load data from a file
def load_data(filepath):
    with open(filepath, 'r') as f:
        data = f.read()
    return data.splitlines()

# Load existing config values from the file
def load_config():
    try:
        with open('config.json', 'r') as file:
            return json.load(file)
    except Exception as e:
        messagebox.showerror("Error", f"Error loading config: {e}")
        return None

# Function to generate the station list
def generate_station_list():
    # Get the selected station names
    selected_stations = [listbox.get(index) for index in listbox.curselection()]

    # Update the desiredWarehouses field in the config.json file with the selected station IDs
    try:
        with open('config.json', 'r') as file:
            config = json.load(file)
            # Map station names to IDs and update the config
            station_id_mapping = {name: station_ids[index] for index, name in enumerate(station_names)}
            config['desiredWarehouses'] = [station_id_mapping[name] for name in selected_stations]
        with open('config.json', 'w') as file:
            json.dump(config, file, indent=2)
            messagebox.showinfo("Success", "Config updated successfully!")
    except Exception as e:
        messagebox.showerror("Error", f"Error updating config: {e}")

# Create main window
root = tk.Tk()
root.title("Station List Generator")

# Load station IDs and names
station_data = load_data('serviceAreaIds')
station_ids = []
station_names = []
for item in station_data:
    station_id, station_name = item.split(':')
    station_ids.append(station_id)
    station_names.append(station_name)

# Load existing config
config = load_config()
selected_ids = config.get('desiredWarehouses', [])

# Create a list box and add the station names
listbox = tk.Listbox(root, selectmode=tk.MULTIPLE)
for station_name in station_names:
    listbox.insert(tk.END, station_name)

# Pre-select stations based on IDs in the config
for index, station_id in enumerate(station_ids):
    if station_id in selected_ids:
        listbox.selection_set(index)

# Create a button to generate the list
button = tk.Button(root, text="Generate List", command=generate_station_list)

# Pack the widgets
listbox.pack(fill=tk.BOTH, expand=True)
button.pack(fill=tk.BOTH)

root.geometry("350x700")
root.resizable(True, True)

root.wm_title("Select filter stations:")
# Run the main loop
root.mainloop()
