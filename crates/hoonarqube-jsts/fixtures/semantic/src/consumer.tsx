import { legacyValue } from "@fixture/index";
import { internalValue } from "./internal";
import declared from "declared-package";
import implicit from "unlisted-package";

export const view = <span>{legacyValue + internalValue + declared + implicit}</span>;
