import npm from "rollup-plugin-node-resolve";

export default {
  entry: "./d3.imports.js",
  format: "iife",
  moduleName: "d3",
  plugins: [npm({jsnext: true})],
  dest: "./scripts/d3.bundle.js"
};
