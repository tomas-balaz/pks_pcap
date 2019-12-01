import os


def parse_configuration(lines):
    protocol_name_by_value = {}
    protocol_value_by_name = {}

    for line in lines:
        if not line.startswith('#'):
            value, name = line.split()
            value = int(value, 0)
            protocol_name_by_value[value] = name
            protocol_value_by_name[name] = value

    return protocol_name_by_value, protocol_value_by_name


def create_config_lines():
    dirname = os.path.dirname(__file__)
    filepath = os.path.join(dirname, f'config.txt')
    config_file = open(filepath, 'r')

    config_lines = []
    for line in config_file:
        config_lines.append(line)

    config_file.close()
    return config_lines


def get_protocol_dicts():
    conf_lines = create_config_lines()
    return parse_configuration(conf_lines)
