import os
import importlib
import inspect
import httpx
import holehe
import logging
import site

def get_functions_from_path(module_path):
    """
    Fetch all callable functions from a given module path.
    """
    try:
        module = importlib.import_module(module_path)
        functions = {name: f"{module_path}.{name}" for name, value in inspect.getmembers(module) if inspect.isfunction(value)}
        logging.info(f"Functions fetched from {module_path}: {list(functions.keys())}")
        return functions
    except Exception as e:
        logging.error(f"Failed to get functions from {module_path}: {e}")
        return {}

def get_all_functions_from_holehe():
    base_module_path = "holehe.modules"
    all_functions = {}

    # Use a more reliable approach to find the site-packages directory
    site_packages_dir = [p for p in site.getsitepackages() if 'site-packages' in p][0]  # this will give us the correct site-packages directory
    modules_dir = os.path.join(site_packages_dir, 'holehe', 'modules')

    logging.info(f"Reading modules from: {modules_dir}")

    if not os.path.exists(modules_dir):
        logging.error(f"Directory does not exist: {modules_dir}")
        return {}
    
    # List all the subdirectories within the 'modules' directory.
    subdirectories = [d for d in os.listdir(modules_dir) if os.path.isdir(os.path.join(modules_dir, d)) and not d.startswith("__")]

    for subdirectory in subdirectories:
        current_dir = os.path.join(modules_dir, subdirectory)
        available_modules = [f[:-3] for f in os.listdir(current_dir) if f.endswith('.py') and not f.startswith('__')]

        logging.info(f"Available modules in {subdirectory}: {available_modules}")

        for module_name in available_modules:
            module_path = f"{base_module_path}.{subdirectory}.{module_name}"
            functions = get_functions_from_path(module_path)
            all_functions.update(functions)

            logging.info(f"Added functions from {module_name}: {list(functions.keys())}")

    return all_functions

async def check_email(email, module_data):
    out = []
    client = httpx.AsyncClient()

    for module_name, module_function_path in module_data.items():
        logging.info(f"Checking {module_name} for email '{email}'.")

        try:
            module, function_name = module_function_path.rsplit('.', 1)
            actual_module = importlib.import_module(module)
            function = getattr(actual_module, function_name)
            
            logging.debug(f"Invoking function: {function_name} which is: {function}")
            
            await function(email, client, out)  # Here's where we pass 'out' 

            if out:
                # I'm assuming the function will append the results to 'out'.
                # So, the last item in 'out' would be the latest result.
                logging.info(f"Module '{module_name}' found: {out[-1]}")
            else:
                logging.info(f"Module '{module_name}' returned no results for the email '{email}'.")

        except IndexError as ie:
            # Handle the specific case of IndexError, which you faced with Snapchat
            logging.warning(f"Error with {module_name}. The site structure might have changed. Error: {ie}")
        except Exception as e:
            # Handle general exceptions
            logging.error(f"Error while checking {module_name}: {e}")

        logging.info(f"Finished checking {module_name} for email '{email}'.")

    await client.aclose()
    return out

