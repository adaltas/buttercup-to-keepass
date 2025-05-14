import fs from "fs/promises";
import {
  Credentials,
  FileDatasource,
  Vault,
  VaultFormatB,
  setDefaultFormat,
  init,
} from "buttercup";
import { stringify } from "csv-stringify/sync";
import { shell } from "shell";

const parse_arguments = () => {
  const app = shell({
    name: "buttercup-to-keepass",
    description:
      "Reads a KeePass vault and export its entries as CSV in a KeePass format.",
    options: {
      columns: {
        description: "Print column names in the first line.",
        shortcut: "i",
        type: "boolean",
      },
      info: {
        description: "Print the vault structure to stdout.",
        shortcut: "i",
        type: "boolean",
      },
      password: {
        description: "Buttercup vault password",
        required: true,
        shortcut: "p",
      },
      source: {
        description: "Buttercup vault location",
        required: true,
        shortcut: "s",
      },
      target: {
        description: "CSV exported file location",
        required: true,
        shortcut: "t",
      },
    },
  });
  try {
    const args = app.parse();
    if (app.helping(args)) {
      process.stdout.write(app.help());
      process.exit();
    }
    return args;
  } catch (err) {
    process.stdout.write(app.help());
    process.exit(1);
  }
};

const open_vault = async (args) => {
  // See https://buttercup.github.io/core-docs/#/usage/basic
  init();
  setDefaultFormat(VaultFormatB);
  const datasourceCredentials = Credentials.fromDatasource(
    {
      type: "file",
      path: args.source,
    },
    args.password,
  );
  const datasource = new FileDatasource(datasourceCredentials);
  const loadedState = await datasource.load(
    Credentials.fromPassword(args.password),
  );
  return Vault.createFromHistory(loadedState.history, loadedState.Format);
};

const concert_to_records = (args, vault) => {
  const records = [];
  const walk = ({ group, depth = 0, parents = [] }) => {
    if (depth === 0) {
      if (args.info) process.stdout.write("vault\n");
    } else {
      if (args.info)
        process.stdout.write(
          " ".repeat(depth * 2) + "- " + group.getTitle() + "\n",
        );
      for (const entry of group.getEntries()) {
        if (args.info)
          process.stdout.write(
            " ".repeat(depth * 2) + "  " + entry._source.p.title.value + "\n",
          );
        // https://keepass.info/help/kb/imp_csv.html
        const record = {
          Group: [...parents, group.getTitle()].join("/"),
          Title: entry._source.p.title.value,
          Username: entry._source.p.username?.value,
          Password: entry._source.p.password?.value,
          URL: entry._source.p.url?.value,
          Notes: entry._source.p.notes?.value,
          TOTP: entry._source.p.otp?.value,
        };
        for (const attribute in entry._source.p) {
          if (
            ["title", "username", "password", "url", "notes", "otp"].includes(
              attribute,
            )
          )
            continue;
          if (entry._source.p[attribute].value) {
            if (!record.Notes) {
              record.Notes = "";
            } else {
              record.Notes += "\n\n";
            }
            record.Notes +=
              `# ${attribute}` + "\n\n" + entry._source.p[attribute].value;
          }
        }
        records.push(record);
      }
    }
    for (const child of group.getGroups()) {
      walk({
        group: child,
        depth: depth + 1,
        parents: [...parents, depth === 0 ? "" : group.getTitle()],
      });
    }
  };
  walk({ group: vault });
  return records;
};

const write_csv = async (args, records) => {
  const data = stringify(records, {
    header: args.columns,
    columns: ["Group", "Title", "Username", "Password", "URL", "Notes", "TOTP"],
  });
  await fs.writeFile(args.target, data);
};

const args = parse_arguments();
const vault = await open_vault(args);
const records = concert_to_records(args, vault);
write_csv(args, records);
