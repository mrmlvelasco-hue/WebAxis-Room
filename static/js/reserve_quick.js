document.addEventListener("DOMContentLoaded", function () {

    console.log("reserve_quick loaded");

    if (typeof ROOMS === "undefined") return;

    const quickLocation = document.getElementById("quickLocation");
    const quickRoom = document.getElementById("quickRoom");
    const quickBtn = document.getElementById("quickReserveBtn");

    /* =====================================================
       LOAD LOCATION LIST
    ===================================================== */

    if (quickLocation && quickRoom) {

        const locations = [...new Set(ROOMS.map(r => r.location || "General"))];

        quickLocation.innerHTML = `<option value="">Select Location</option>`;

        locations.forEach(loc => {

            const opt = document.createElement("option");
            opt.value = loc;
            opt.textContent = loc;

            quickLocation.appendChild(opt);

        });

    }

    /* =====================================================
       LOCATION → ROOM LIST
    ===================================================== */

    if (quickLocation && quickRoom) {

        quickLocation.addEventListener("change", function () {

            const location = this.value;

            quickRoom.innerHTML = `<option value="">Select Room</option>`;

            const filteredRooms = ROOMS.filter(r =>
                (r.location || "General") === location
            );

            filteredRooms.forEach(r => {

                const opt = document.createElement("option");
                opt.value = r.id;
                opt.textContent = r.name;

                quickRoom.appendChild(opt);

            });

            /* Auto select first room */
            if (quickRoom.options.length > 1) {

                quickRoom.selectedIndex = 1;

                quickRoom.dispatchEvent(new Event("change"));

            }

        });

    }

    /* =====================================================
       ROOM → UPDATE MODAL
    ===================================================== */

    if (quickRoom) {

        quickRoom.addEventListener("change", function () {

            const roomId = this.value;

            const room = ROOMS.find(r => r.id == roomId);

            if (!room) return;

            const label = document.getElementById("modalRoomLabel");

            if (label) {
                label.textContent = room.name;
            }

            if (typeof renderFeatures === "function") {
                renderFeatures(room.features || "");
            }

        });

    }

    /* =====================================================
       QUICK RESERVE BUTTON
    ===================================================== */

    if (quickBtn) {

        quickBtn.addEventListener("click", function () {

            window.postMessage({
                type: "OPEN_NEW_RESERVATION",
                source: "quick"
            }, "*");

        });

    }

});