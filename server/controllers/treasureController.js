module.exports = {
    dragonTreasure: async (req, res) => {
        const treasure = await req.app.get('db').get_dragon_treasure(1);
        return res.status(200).send(treasure);
    },
    getUserTreasure: async (req, res) => {
        const {id} = req.session.user
        const treasure = await req.app.get('db').get_user_treasure(id)
        return res.status(200).send(treasure)
    },
    addUserTreasure: async (req, res) => {
        const {treasureURL} = req.body
        const {id} = req.session.user
        let userTreasure = await req.app.get('db').add_user_treasure( treasureURL, id )
        res.status(200).send(userTreasure)
    },
    getAllTreasure: async (req, res) => {
        let treasures = await req.app.get('db').get_all_treasure()
        res.status(200).send(treasures)
    }
  };