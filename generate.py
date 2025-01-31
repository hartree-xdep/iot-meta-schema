import pathlib

if __name__ == '__main__':
    with open('domains.txt') as domains_file, open('template.meta-schema.json') as template_file:
        domains, template = domains_file.read().split('\n'), template_file.read()

        for domain in domains:
            domain = domain.strip().split('#', maxsplit=1)[0].strip()
            if not domain or domain.startswith('#'): # empty line or comment
                continue

            meta_schema = template.replace(r'$domain', domain)
            parent_dir = pathlib.Path(f'generated/{domain}')
            parent_dir.mkdir(exist_ok=True)

            with open(parent_dir / 'meta-schema', 'w') as output_file:
                output_file.write(meta_schema)
