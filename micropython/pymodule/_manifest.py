def __manifest_add_modules():
    import os
    for name in os.listdir('.'):
        if name.endswith('.py') and \
                not name.startswith('.') and \
                not name.startswith('_'):
            module(name)


module('natter.py', base_path='../..')
__manifest_add_modules()

del __manifest_add_modules
