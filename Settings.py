import json
import tkinter as tk
from tkinter import messagebox

# Load existing config values from the file
def load_config():
    try:
        with open('config.json', 'r') as file:
            config = json.load(file)
            # Select only the desired keys
            desired_keys = [
                "minBlockRate", "minPayRatePerHour", "arrivalBuffer",
                "desiredWarehouses", "desiredStartTime", "desiredEndTime",
                "desiredWeekdays", "retryLimit", "refreshInterval",
                "twilioAcctSid", "twilioAuthToken", "twilioFromNumber", "twilioToNumber"
            ]
            # Check and update the format of desiredWarehouses and desiredWeekdays
            for key in ["desiredWarehouses"]:
                if key in config and not isinstance(config[key], list):
                    config[key] = []
            return {key: config.get(key, "") for key in desired_keys}
    except Exception as e:
        messagebox.showerror("Error", f"Error loading config: {e}")
        return None

# Save the modified config back to the file
def save_config():
    try:
        with open('config.json', 'r') as file:
            config = json.load(file)
            for entry in entry_fields:
                key = entry["key"]
                # Check if the field is desiredWeekdays
                if key == "desiredWeekdays":
                    selected_days = [day for day, var in zip(["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"], weekday_vars) if var.get()]
                    value = selected_days
                    # Update the format to list if necessary
                    if not value:
                        value = []
                elif key in ["desiredWarehouses"]:
                    # Update the format to list if necessary
                    if not isinstance(value, list):
                        value = []
                else:
                    value = entry["entry"].get()

                    # Check if the value is numeric
                    if key in ["minBlockRate", "minPayRatePerHour", "arrivalBuffer", "retryLimit", "refreshInterval"]:
                        try:
                            # Try converting the value to a float or int
                            value = float(value)
                            if value.is_integer():
                                value = int(value)
                        except ValueError:
                            # If conversion fails, display an error message
                            messagebox.showerror("Error", f"Invalid value for {key}. Must be a number.")
                            return

                config[key] = value

        with open('config.json', 'w') as file:
            json.dump(config, file, indent=2)
            messagebox.showinfo("Success", "Config saved successfully!")
    except Exception as e:
        messagebox.showerror("Error", f"Error saving config: {e}")

# Create main window
root = tk.Tk()
root.title("Config Editor")

# Load existing config values
config = load_config()
if config is None:
    root.destroy()
    exit()

# Custom labels for each configuration parameter
custom_labels = {
    "minBlockRate": "Minimum Block Rate:",
    "minPayRatePerHour": "Minimum Pay Rate per Hour:",
    "arrivalBuffer": "Arrival Buffer:",
    "desiredWarehouses": "Desired Warehouses:",
    "desiredStartTime": "Desired Start Time:",
    "desiredEndTime": "Desired End Time:",
    "desiredWeekdays": "Desired Weekdays:",
    "retryLimit": "Retry Limit:",
    "refreshInterval": "Refresh Interval:",
    "twilioAcctSid": "Twilio Account SID:",
    "twilioAuthToken": "Twilio Auth Token:",
    "twilioFromNumber": "Twilio From Number:",
    "twilioToNumber": "Twilio To Number:"
}

# Create and pack labels and entry fields for specific config parameters
entry_fields = []
for i, (key, value) in enumerate(config.items()):
    label_text = custom_labels.get(key, key)  # Use custom label if available, otherwise use key
    label = tk.Label(root, text=label_text)
    label.grid(row=i, column=0, sticky="w", padx=5, pady=5)

    if key == "desiredWeekdays":
        # Create check buttons for each day of the week
        weekday_vars = []
        for j, day in enumerate(["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]):
            var = tk.BooleanVar()
            var.set(day in value)  # Set the initial state based on the loaded config
            weekday_vars.append(var)

            checkbox = tk.Checkbutton(root, text=day, variable=var)
            checkbox.grid(row=i, column=1 + j, padx=5, pady=5, sticky="w")

        entry_fields.append({"key": key, "vars": weekday_vars})
    else:
        entry = tk.Entry(root, width=40)
        entry.grid(row=i, column=1, columnspan=7, padx=5, pady=5)
        entry.insert(tk.END, value)

        entry_fields.append({"key": key, "entry": entry})

# Create and pack save button
save_button = tk.Button(root, text="Save Config", command=save_config)
save_button.grid(row=len(config), columnspan=8, pady=10)

# Run the Tkinter event loop
root.mainloop()
