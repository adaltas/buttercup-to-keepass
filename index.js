#!/usr/bin/env node

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
        shortcut: "c",
        type: "boolean",
      },
      info: {
        description: "Print the vault structure to stdout.",
        shortcut: "i",
        type: "boolean",
      },
      otp: {
        description: "List of properties interpreted as OTP code.",
        default: ["otp"],
        shortcut: "o",
        type: "array",
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
        // See https://github.com/adaltas/buttercup-to-keepass/issues/8
        // Two format are encountered to store properties values:
        // - `entry._source.p[property].value`
        // - `entry._source.properties[propery]`
        const properties = entry._source.p || entry._source.properties;
        for (const k in properties) {
          if (!properties[k].value === undefined) continue;
          properties[k] = properties[k].value;
        }
        if (args.info)
          process.stdout.write(
            " ".repeat(depth * 2) + "  " + properties.title + "\n",
          );
        // https://keepass.info/help/kb/imp_csv.html
        const otp = args.otp.find((otp) => properties[otp]);
        const record = {
          Group: [...parents, group.getTitle()].join("/"),
          Title: properties.title,
          Username: properties.username,
          Password: properties.password,
          URL: properties.url,
          Notes: properties.notes,
          TOTP: properties[otp],
        };
        for (const property in properties) {
          if (
            [
              "title",
              "username",
              "password",
              "url",
              "notes",
              ...args.otp,
            ].includes(property)
          )
            continue;
          if (properties[property]) {
            if (!record.Notes) {
              record.Notes = "";
            } else {
              record.Notes += "\n\n";
            }
            record.Notes += `# ${property}` + "\n\n" + properties[property];
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
