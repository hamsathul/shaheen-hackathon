// The threat summary's print button: the browser's print dialog, where "Save as PDF" is a printer.
(function () {
  "use strict";
  document.getElementById("print").addEventListener("click", function () {
    window.print();
  });
})();
