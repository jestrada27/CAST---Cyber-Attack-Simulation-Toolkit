//==============================================================================================================================================================
// UI Elements
//==============================================================================================================================================================
const layout = document.getElementById("layout");
//The container that holds all the group buttons
const groupButtonContainer = document.querySelector("#groupButtonContainer");
//The button that creates a group button
const buttonCreateGroup = document.querySelector("#buttonCreateGroup");
//The modal that pops up when the user wants to create a new group
const createGroupModal = document.getElementById("createGroupModal");
//The button that closes the createGroupModal
const createGroupModalCloseButton = document.getElementById("createGroupModalCloseBtn");
// The options modal overlay for the member buttons
const memberModalOverlay = document.getElementById("memberModalOverlay");
// The options modal for the member buttons
const memberModal = document.getElementById("memberModal");
//The button to toggle the member sidebar
const toggleRightSidebarbtn = document.getElementById("toggleSidebar");
//The member sidebar.
const rightSidebar = document.getElementById("rightSidebar");
//The options modal overlay for te group buttons
const groupModalOverlay = document.getElementById("groupModalOverlay");
//The options modal for the group buttons
const groupModal = document.getElementById("groupModal");
// The container that holds the member buttons
const memberContainer = document.querySelector("#memberContainer");

//==============================================================================================================================================================
// Functions
//==============================================================================================================================================================

//Selects the first applicable group
function SelectNewGroup() {
    if (groupButtonContainer.children.length > 0) {
        groupButtonContainer.children[0].classList.add("is-selected");
        groupButtonContainer.children[0].click();
    }
}

//Creates a new group button and adds it to the list.
function CreateButtonForGroup(groupName) {
    const button = document.createElement("button");
    button.textContent = groupName;
    button.className = "item";
    //This will display the new page for the dashboard
    button.addEventListener("click", () => {
        //TODO: Display the stuff in the dashboard page
        console.log("clicked");
    });

    //This brings up the group modal options
    button.addEventListener("contextmenu", (event) => {
        event.preventDefault(); // stops the browser menu
        DisplayModal(groupModalOverlay, groupModal, false, event);
    });

    //Add the button to the container
    document.getElementById("groupButtonContainer").appendChild(button);
    if (document.getElementById("groupButtonContainer").children.length === 1) {
        SelectNewGroup();
    }
}

//TODO: maybe move this to a project wide js file?
/**
 * Displays modal
 * @param modalOverlay The overlay responsible for the modal
 * @param modal The actual modal, the content
 * @param bLeftHanded Should the modal be displayed on the left or right side of the cursor
 * @param e The click event that caused the modal to be displayed
*/
function DisplayModal(modalOverlay, modal, bLeftHanded, e) {
    modalOverlay.style.display = "block";

    const modalWidth = modal.offsetWidth;
    const padding = 10;


    let xPos = 0;

    if (bLeftHanded) {
        xPos = e.clientX - modalWidth - padding;
    } else {
        xPos = e.clientX + padding;
    }

    let top = e.clientY + padding;

    if (xPos < padding) xPos = padding;
    if (top + modal.offsetHeight > window.innerHeight) {
        top = window.innerHeight - modal.offsetHeight - padding;
    }

    modal.style.left = `${xPos}px`;
    modal.style.top = `${top}px`;

}

//TODO: maybe move this to a project wide js file?
function closeModalFn(modalOverlay) {
    modalOverlay.style.display = "none";
}

async function loadUserGroups() {
    try {
        const res = await fetch("/groups/user_group", {
            method: "GET",
            headers: { "Accept": "application/json" },
            // IMPORTANT if your frontend is on a different domain/port:
            // credentials: "include",
        });

        // Handle not-logged-in (401)
        if (res.status === 401) {
            const err = await res.json();
            console.log("Not logged in:", err.message);
            // e.g. redirect:
            // window.location.href = "/login";
            return;
        }

        if (!res.ok) {
            throw new Error(`Request failed: ${res.status}`);
        }

        const data = await res.json(); // { groups: ... }

        // Do stuff with it:
        console.log("Groups:", data.groups);
        renderGroups(data.groups);

    } catch (e) {
        console.error("Error loading groups:", e);
    }
}

function renderGroups(groups) {
    for (const g of groups) {
        CreateButtonForGroup(g.name);
    }
    return;
}

async function createUserGroup(name) {
    const res = await fetch("/groups/create_user_group", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        body: JSON.stringify({ name }),
        // If frontend is on a different origin/port, uncomment:
        // credentials: "include",
    });

    const data = await res.json().catch(() => ({})); // in case non-JSON error

    if (res.status === 401) {
        // Not logged in
        console.log(data.message || "Not logged in");
        // window.location.href = "/login";
        return;
    }

    if (res.status === 400) {
        // Validation error (e.g., missing name)
        alert(data.message || "Bad request");
        return;
    }

    if (!res.ok) {
        console.error("Server error:", res.status, data);
        alert("Something went wrong.");
        return;
    }

    // Success
    console.log("Created group:", data);
    // data = { success: true, group_id: "...", user_key: "...", admin_key: "..." }
    return data;
}

//==============================================================================================================================================================
// Setup
//==============================================================================================================================================================


// Group selection logic
groupButtonContainer.addEventListener("click", (e) => {
    const clicked = e.target.closest("button");
    if (!clicked) return;

    groupButtonContainer.querySelectorAll(".item.is-selected").forEach((item) => {
        item.classList.remove("is-selected");
    });

    clicked.classList.add("is-selected");
});

//Setup close button for create group modal
createGroupModalCloseButton.addEventListener("click", () => {
    createGroupModal.classList.remove("show");
    document.getElementById("createGroupNameInput").value = "";
});

//Setup create group modal submit handler
document.getElementById("createGroupForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const groupName = document.getElementById("createGroupNameInput").value;
    console.log(groupName);

    createUserGroup(groupName)
        .then(result => {
            CreateButtonForGroup(groupName);
            console.log(result.group_id);
        })
        .catch(err => {
            console.error(err.message);
        });


    document.getElementById("createGroupNameInput").value = "";
    createGroupModal.classList.remove("show");

});

//Setup the createGroupButton to show the create group modal
buttonCreateGroup.addEventListener("click", (e) => {
    createGroupModal.classList.add("show");
});

//Setup the collapsing member sidebar logic
toggleRightSidebarbtn.addEventListener("click", () => {
    const collapsed = layout.classList.toggle("is-collapsed");
    toggleRightSidebarbtn.setAttribute("aria-expanded", String(!collapsed));
});

// Setup the Close when clicking outside member modal logic
memberModalOverlay.addEventListener("click", (e) => {

    if (!memberModal.contains(e.target)) {
        closeModalFn(memberModalOverlay);
    }
});

// Setup the Close when clicking outside group modal logic
groupModalOverlay.addEventListener("click", (e) => {
    if (!groupModal.contains(e.target)) {
        closeModalFn(groupModalOverlay);
    }
});

//Setup the display modal when member button clicked logic
memberContainer.addEventListener("click", (e) => {
    const clicked = e.target.closest("button");
    if (!clicked) return;
    DisplayModal(memberModalOverlay, memberModal, true, e);
});

//Load the user groups when we first load the page
loadUserGroups();