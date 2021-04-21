Opening a Network
=================

This sections assumes that a set of nodes has already been started by :term:`Operators`. See :doc:`/operations/start_network`.


Adding Users
------------

Once a CCF network is successfully started and an acceptable number of nodes have joined, members should vote to open the network to :term:`Users`. First, :doc:`the identities of trusted users should be generated </use_apps/index>`.

Then, the certificates of trusted users should be registered in CCF via the member governance interface. For example, the first member may decide to make a proposal to add a new user (here, ``user_cert`` is the PEM certificate of the user -- see :ref:`overview/cryptography:Cryptography` for a list of supported algorithms):

.. code-block:: bash

    $ cat set_user.json
    {
        "actions": [
            {
                "name": "set_user",
                "args": {
                    "cert": "-----BEGIN CERTIFICATE-----\nMIIBs...<SNIP>...yR\n-----END CERTIFICATE-----\n"
                }
            }
        ]
    }

    $ scurl.sh https://<ccf-node-address>/gov/proposals --cacert network_cert --key member0_privk --cert member0_cert --data-binary @add_user.json -H "content-type: application/json"
    {
        "ballot_count": 0,
        "proposal_id": "f665047e3d1eb184a7b7921944a8ab543cfff117aab5b6358dc87f9e70278253",
        "proposer_id": "2af6cb6c0af07818186f7ef7151061174c3cb74b4a4c30a04a434f0c2b00a8c0",
        "state": "Open"
    }

Other members are then allowed to vote for the proposal, using the proposal id returned to the proposer member. They may submit an unconditional approval, or their vote may query the current state and the proposed actions. These votes `must` be signed.

.. code-block:: bash

    $ cat vote_accept.json
    {
        "ballot": "export function vote (proposal, proposerId) { return true }"
    }

    $ scurl.sh https://<ccf-node-address>/gov/proposals/f665047e3d1eb184a7b7921944a8ab543cfff117aab5b6358dc87f9e70278253/votes --cacert network_cert --key member1_privk --cert member1_cert --data-binary @vote_accept.json -H "content-type: application/json"
    {
        "ballot_count": 1,
        "proposal_id": "f665047e3d1eb184a7b7921944a8ab543cfff117aab5b6358dc87f9e70278253",
        "proposer_id": "2af6cb6c0af07818186f7ef7151061174c3cb74b4a4c30a04a434f0c2b00a8c0",
        "state": "Open"
    }

    $ cat vote_conditional.json
    {
        "ballot": "export function vote (proposal, proposerId) { return proposerId == \"2af6cb6c0af07818186f7ef7151061174c3cb74b4a4c30a04a434f0c2b00a8c0\" }"
    }

    $ scurl.sh https://<ccf-node-address>/gov/proposals/f665047e3d1eb184a7b7921944a8ab543cfff117aab5b6358dc87f9e70278253/votes --cacert network_cert --key member2_privk --cert member2_cert --data-binary @vote_conditional.json -H "content-type: application/json"
    {
        "ballot_count": 2,
        "proposal_id": "f665047e3d1eb184a7b7921944a8ab543cfff117aab5b6358dc87f9e70278253",
        "proposer_id": "2af6cb6c0af07818186f7ef7151061174c3cb74b4a4c30a04a434f0c2b00a8c0",
        "state": "Accepted"
    }

The user is successfully added once a the proposal has received enough votes under the rules of the :term:`Constitution` (indicated by the response body showing a transition to state ``ACCEPTED``).

The user can then make user RPCs.

User Data
---------

For each user, CCF also stores arbitrary user-data in a JSON object. This can only be written to by members, subject to the standard proposal-vote governance mechanism, via the ``set_user_data`` action. This lets members define initial metadata for certain users; for example to grant specific privileges, associate a human-readable name, or categorise the users. This user-data can then be read (but not written) by user-facing endpoints.

For example, the ``/log/private/admin_only`` endpoint in the C++ logging sample app uses user-data to restrict who is permitted to call it:

.. literalinclude:: ../../samples/apps/logging/logging.cpp
    :language: cpp
    :start-after: SNIPPET_START: user_data_check
    :end-before: SNIPPET_END: user_data_check
    :dedent:

Members configure this permission with ``set_user_data`` proposals:

.. code-block:: bash

    $ cat set_user_data_proposal.json
    {
        "script": {
            "text": "tables, args = ...; return Calls:call(\"set_user_data\", args)"
        },
        "parameter": {
            "user_id": "f30db4b4d40d8c495d0c25e920d839876c8dc12e3e561cc9b337ab768e60e06a",
            "user_data": {
                "isAdmin": true
            }
        }
    }

Once this proposal is accepted, user 0 is able to use this endpoint:

.. code-block:: bash

    $ curl https://<ccf-node-address>/app/log/private/admin_only --key user0_privk.pem --cert user0_cert.pem --cacert networkcert.pem -X POST --data-binary '{"id": 42, "msg": "hello world"}' -H "Content-type: application/json" -i
    HTTP/1.1 200 OK

    true

All other users have empty or non-matching user-data, so will receive a HTTP error if they attempt to access it:

.. code-block:: bash

    $ curl https://<ccf-node-address>/app/log/private/admin_only --key user1_privk.pem --cert user1_cert.pem --cacert networkcert.pem -X POST --data-binary '{"id": 42, "msg": "hello world"}' -H "Content-type: application/json" -i
    HTTP/1.1 403 Forbidden

    Only admins may access this endpoint

Opening the Network
-------------------

Once users are added to the opening network, members should create a proposal to open the network:

.. code-block:: bash

    $ cat transition_service_to_open.json
    {
        "actions": [
            {
                "name": "transition_service_to_open",
                "args": null
            }
        ]
    }

    $ scurl.sh https://<ccf-node-address>/gov/proposals --cacert network_cert --key member0_privk --cert member0_cert --data-binary @transition_service_to_open.json -H "content-type: application/json"
    {
        "ballot_count": 0,
        "proposal_id": "77374e16de0b2d61f58aec84d01e6218205d19c9401d2df127d893ce62576b81",
        "proposer_id": "2af6cb6c0af07818186f7ef7151061174c3cb74b4a4c30a04a434f0c2b00a8c0",
        "state": "Open"
    }

Other members are then able to vote for the proposal using the returned proposal id.

Once the proposal has received enough votes under the rules of the :term:`Constitution` (``"result":true``), the network is opened to users. It is only then that users are able to execute transactions on the business logic defined by the enclave file (``--enclave-file`` option to ``cchost``).
